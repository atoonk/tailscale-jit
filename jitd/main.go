// Command jitd is a proof-of-concept just-in-time access service for Tailscale
// Services. It runs as its own tailnet node (tsnet), identifies callers with
// WhoIs, and grants approved access by setting a custom device posture
// attribute with an expiry through the Tailscale API.
//
// Logs go to stderr.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"tailscale.com/tsnet"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/jithttp"
	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

func main() {
	hostname := flag.String("hostname", "jit", "tailnet hostname for this node")
	stateDir := flag.String("state-dir", "tsnet-state", "directory for the tsnet node state (keep it; otherwise the node re-registers)")
	dataPath := flag.String("data", "jit.db", "SQLite database for approval flows and access requests. Upgrading from an older jitd: name its .json data file, and jitd uses the .db of the same name, filled from the .json the first time (a new jit.db also picks up jit-data.json next to it). The .json is left alone")
	apiBase := flag.String("ts-api", tsapi.DefaultBaseURL, "Tailscale API base URL")
	envFile := flag.String("env-file", defaultEnvFile(), "file with the Tailscale API credentials (TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET, or TS_API_KEY), one KEY=VALUE per line; the environment is used for anything the file lacks")
	jitTag := flag.String("tag", "tag:jit", "tag this node runs as (used in the policy snippet)")
	expiryInterval := flag.Duration("expiry-interval", 30*time.Second, "how often to mark approved requests past their expiry as expired")
	policySnippet := flag.Bool("policy-snippet", false, "print the policy-file snippet for the current approval flows and exit")
	admins := flag.String("admins", "", "comma-separated principals who may manage approval flows and see every request (logins, group:, tag:); nobody if empty")
	https := flag.Bool("https", false, "serve HTTPS on :443 with a Tailscale certificate (needs HTTPS enabled for the tailnet); :80 then redirects")
	verbose := flag.Bool("verbose", false, "log tsnet backend and every HTTP request")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: jitd [flags]\n\njitd grants just-in-time access on a tailnet. "+
			"Install guide and docs: https://github.com/atoonk/tailscale-jit/tree/main/jitd\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *policySnippet {
		store, err := jit.OpenReadOnly(*dataPath)
		if err != nil {
			log.Error("cannot read the database", "err", err)
			os.Exit(1)
		}
		defer store.Close()
		fmt.Print((&jit.Service{Store: store}).PolicySnippet(*jitTag))
		return
	}

	store, err := jit.Open(*dataPath)
	if err != nil {
		log.Error("cannot use the database", "err", err)
		os.Exit(1)
	}
	defer store.Close()
	switch {
	case store.Imported != "":
		log.Info("imported the old JSON data file into the database; the JSON file is no longer read, keep it as a backup",
			"from", store.Imported, "into", store.Path)
	case store.Ignored != "":
		log.Info("using the database; the JSON file it was imported from is no longer read", "database", store.Path, "json", store.Ignored)
	}
	if store.Mode&0o077 != 0 {
		log.Warn("other users can read the database; run: chmod 600 "+store.Path, "mode", store.Mode)
	}
	svc := &jit.Service{Store: store, Log: log, UIPorts: []string{"tcp:80"}}
	if *https {
		svc.UIPorts = []string{"tcp:80", "tcp:443"} // :80 redirects to :443
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The API client is filled in by the setup check, and replaced whenever
	// an admin re-runs it, so fixing the credentials needs no restart.
	ts := &tsapi.Switchable{}
	svc.TS = ts
	svc.PolicyCache = &jit.PolicyCache{TS: ts, TTL: time.Minute, Log: log}
	for _, a := range strings.Split(*admins, ",") {
		if a = strings.TrimSpace(a); a != "" {
			if err := jit.ValidatePrincipal(jit.Principal(a)); err != nil {
				log.Error("-admins", "err", err)
				os.Exit(1)
			}
			svc.Admins = append(svc.Admins, jit.Principal(a))
		}
	}
	if len(svc.Admins) == 0 {
		log.Warn("no -admins configured: nobody can manage approval flows or see other people's requests")
	} else if !slices.ContainsFunc(svc.Admins, jit.Principal.IsLogin) {
		// group: and tag: admins are resolved through the Tailscale API: if
		// the credential is missing or broken, nobody can reach the Setup
		// page to fix it.
		log.Warn("-admins lists no login: if the Tailscale API credential is missing or broken, group admins cannot be resolved and nobody can open /admin/setup; add at least one login")
	}

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		log.Error("creating state dir", "err", err)
		os.Exit(1)
	}
	srv := &tsnet.Server{
		Hostname: *hostname,
		Dir:      *stateDir,
		UserLogf: func(format string, args ...any) {
			log.Info("tsnet: " + strings.TrimSpace(fmt.Sprintf(format, args...)))
		},
	}
	if *verbose {
		srv.Logf = func(format string, args ...any) {
			log.Debug("tsnet backend: " + strings.TrimSpace(fmt.Sprintf(format, args...)))
		}
	}
	defer srv.Close()

	log.Info("starting tsnet node", "hostname", *hostname, "state_dir", *stateDir, "auth_key_set", os.Getenv("TS_AUTHKEY") != "")
	st, err := srv.Up(ctx)
	if err != nil {
		log.Error("tsnet up", "err", err)
		os.Exit(1)
	}
	var ips []string
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip.String())
	}
	dns := ""
	if st.Self != nil {
		dns = strings.TrimSuffix(st.Self.DNSName, ".")
	}
	log.Info("tsnet node up", "dns_name", dns, "ips", ips)

	lc, err := srv.LocalClient()
	if err != nil {
		log.Error("tsnet local client", "err", err)
		os.Exit(1)
	}
	checker := &setup.Checker{
		EnvFile: *envFile,
		APIBase: *apiBase,
		Tag:     *jitTag,
		Target:  ts,
		Log:     log,
		Node: func(ctx context.Context) (setup.Node, error) {
			st, err := lc.StatusWithoutPeers(ctx)
			if err != nil {
				return setup.Node{}, err
			}
			if st.Self == nil {
				return setup.Node{}, errors.New("no self node in status")
			}
			n := setup.Node{ID: string(st.Self.ID), DNSName: strings.TrimSuffix(st.Self.DNSName, ".")}
			if st.Self.Tags != nil {
				n.Tags = st.Self.Tags.AsSlice()
			}
			return n, nil
		},
	}
	// Check at startup, and keep retrying while the failure is transient
	// (e.g. the network is not up yet): the result decides whether approvals
	// can work, and nobody may be around to click "Check again".
	go func() {
		wait := 10 * time.Second
		for checker.Run(ctx).Transient {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, 5*time.Minute)
		}
	}()

	scheme := "http"
	if *https {
		scheme = "https"
	}
	h := &jithttp.Server{
		Svc:      svc,
		Resolver: &jit.WhoIsResolver{Client: lc, Timeout: 5 * time.Second},
		TS:       ts,
		Setup:    checker,
		JITTag:   *jitTag,
		BaseURL:  scheme + "://" + cmp.Or(dns, *hostname),
		Hosts:    append([]string{*hostname, dns, strings.Split(dns, ".")[0]}, ips...),
		Log:      log,
	}
	var ln net.Listener
	if *https {
		ln, err = srv.ListenTLS("tcp", ":443")
		if err == nil {
			// Plain HTTP only redirects, so old links and "http://jit" keep working.
			var plain net.Listener
			if plain, err = srv.Listen("tcp", ":80"); err == nil {
				redirect := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, h.BaseURL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
				})}
				go redirect.Serve(plain)
				defer redirect.Close()
			}
		}
	} else {
		ln, err = srv.Listen("tcp", ":80")
	}
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	hs := &http.Server{Handler: h.Handler(), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		svc.ExpireDue()
		t := time.NewTicker(*expiryInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				svc.ExpireDue()
			}
		}
	}()

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()

	log.Info("serving", "url", h.BaseURL+"/")
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// defaultEnvFile is <user config dir>/jitd/env, e.g. ~/.config/jitd/env.
func defaultEnvFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "jitd.env"
	}
	return filepath.Join(dir, "jitd", "env")
}
