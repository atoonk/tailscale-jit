// Command pamagent is the small local helper for jitd, the just-in-time access
// service for Tailscale PAM. jitd itself is the MCP server (http://jit/mcp);
// pamagent only adds what has to run on the agent's own machine:
//
//	pamagent wait <id>     waits for a request's decision and for the granted
//	                       Tailscale Services to show up on this node
//	pamagent bridge        an MCP server on stdin/stdout that forwards to
//	                       jitd's /mcp, for hosts that only run local servers
//	                       (Claude Desktop); also what a bare "pamagent" does
//
// It needs no configuration or credentials: jitd identifies the caller by its
// Tailscale connection.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tailscale.com/client/local"
)

var version = "0.6.1"

// defaultJITURL is where jitd answers on a tailnet with MagicDNS.
const defaultJITURL = "http://jit"

// repoURL is where pamagent, jitd and their docs live.
const repoURL = "https://github.com/atoonk/tailscale-jit"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "wait" {
		os.Exit(runWait(os.Args[2:]))
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "bridge" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("pamagent", flag.ContinueOnError)
	jitURL := fs.String("jit-url", defaultJITURL, "base URL of jitd")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: pamagent [bridge] [-jit-url URL]   MCP server on stdin/stdout, forwarding to jitd's /mcp\n"+
			"       pamagent wait [flags] <request_id>\n\n"+
			"Claude Code and other hosts that speak HTTP need no pamagent: point them at %s/mcp.\n\nDocs: %s/tree/main/pamagent\n\n", defaultJITURL, repoURL)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			fs.Usage()
		}
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runBridge(ctx, *jitURL, log))
}

// serviceNames parses -service: comma-separated, "svc:" added if missing.
func serviceNames(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			if !strings.HasPrefix(n, "svc:") {
				n = "svc:" + n
			}
			out = append(out, n)
		}
	}
	return out
}

// runWait implements "pamagent wait [flags] <request_id>".
func runWait(args []string) int {
	fs := flag.NewFlagSet("pamagent wait", flag.ContinueOnError)
	jitURL := fs.String("jit-url", defaultJITURL, "base URL of jitd")
	socket := fs.String("socket", "", "tailscaled LocalAPI socket path (default: platform default)")
	interval := fs.Duration("interval", 0, "ask jitd at this fixed interval instead of the default backoff (every 3s for 2 minutes, every 20s until 10 minutes, then every minute)")
	service := fs.String("service", "", "after approval, wait until these Tailscale Services are visible (comma-separated, e.g. svc:server01); by default, until any service the approval grants is")
	timeout := fs.Duration("timeout", 5*time.Minute, "stop waiting after this long; the request stays pending and wait can be run again")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: pamagent wait [flags] <request_id>\n\nWaits until a jitd access request is decided; "+
			"if approved, also until the services you need (-service) are visible to this node.\nIt asks every 3s for the first 2 minutes, every 20s until 10 minutes, then every minute.\n"+
			"Exit status: 0 approved, 1 declined/cancelled/revoked/expired, 2 error, 3 still pending when -timeout ran out.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		if err == nil {
			fs.Usage()
		}
		return 2
	}
	sig, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(sig, *timeout)
	defer cancel()
	c := &jitClient{base: *jitURL, hc: &http.Client{Timeout: 15 * time.Second}}
	sched := backoff
	if *interval > 0 {
		sched = func(time.Duration) time.Duration { return *interval }
	}
	return waitForRequest(ctx, sig, c, &local.Client{Socket: *socket}, fs.Arg(0), serviceNames(*service), sched, time.Minute, os.Stdout)
}
