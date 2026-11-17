// The preview serves the jitd web UI on localhost with made-up people and
// a fake Tailscale API, for looking at the UI as different roles without a
// tailnet. Pick who you are at /as/<name> (alice, bob, carol, dave, root).
//
//	go run ./jitd/preview -listen 127.0.0.1:8099
package main

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/googlesetup"
	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/jithttp"
	"github.com/atoonk/tailscale-jit/jitd/internal/jitmcp"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
	"github.com/atoonk/tailscale-jit/jitd/internal/oktasetup"
	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
	"github.com/atoonk/tailscale-jit/jitd/internal/slackbot"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// People to preview as. bob approves several flows but is no admin; carol is in
// group:sre; dave is a plain member; root is the admin.
var people = map[string]jit.Identity{
	"alice": {Login: "alice@example.com", DisplayName: "Alice Park", DeviceID: "nALICE", DeviceName: "alice-macbook"},
	"bob":   {Login: "bob@example.com", DisplayName: "Bob Lin", DeviceID: "nBOB", DeviceName: "bob-thinkpad"},
	"carol": {Login: "carol@example.com", DisplayName: "Carol Diaz", DeviceID: "nCAROL", DeviceName: "carol-mba"},
	"dave":  {Login: "dave@example.com", DisplayName: "Dave Osei", DeviceID: "nDAVE", DeviceName: "dave-laptop"},
	"root":  {Login: "root@example.com", DisplayName: "Root Admin", DeviceID: "nROOT", DeviceName: "admin-mac"},
}

// fakeTS keeps attributes in memory and serves a fixed policy.
// refusedTS answers like the Tailscale API does to a credential it does
// not know.
type refusedTS struct{ tsapi.Client }

var errRefused = &tsapi.APIError{Method: "GET", Path: "/api/v2/tailnet/-/acl", Status: 401, Body: `{"message":"API token invalid"}`}

func (refusedTS) GetPolicy(context.Context) (tsapi.Policy, error) { return tsapi.Policy{}, errRefused }
func (refusedTS) GetAttributes(context.Context, string) (tsapi.Attributes, error) {
	return tsapi.Attributes{}, errRefused
}

type fakeTS struct {
	mu     sync.Mutex
	attrs  map[string]time.Time // device|key -> expiry
	policy *tsapi.Policy        // nil: the default preview policy
}

func (f *fakeTS) SetAttribute(ctx context.Context, device, key string, value any, expiry time.Time, comment string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attrs[device+"|"+key] = expiry
	return nil
}
func (f *fakeTS) GetAttributes(ctx context.Context, device string) (tsapi.Attributes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := tsapi.Attributes{Attributes: map[string]any{}, Expiries: map[string]time.Time{}}
	for k, exp := range f.attrs {
		if dev, key, ok := strings.Cut(k, "|"); ok && dev == device && exp.After(time.Now()) {
			out.Attributes[key] = true
			out.Expiries[key] = exp
		}
	}
	return out, nil
}
func (f *fakeTS) DeleteAttribute(ctx context.Context, device, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.attrs, device+"|"+key)
	return nil
}

// ListDevices lists one device per preview person (for /jit request).
func (f *fakeTS) ListDevices(ctx context.Context) ([]tsapi.Device, error) {
	var out []tsapi.Device
	for _, p := range people {
		out = append(out, tsapi.Device{NodeID: p.DeviceID, Name: p.DeviceName + ".example.ts.net", User: p.Login, Tags: p.Tags,
			OS: "macOS", Authorized: true, ConnectedToControl: true})
	}
	return out, nil
}

func (f *fakeTS) GetPolicy(ctx context.Context) (tsapi.Policy, error) {
	if f.policy != nil {
		return *f.policy, nil
	}
	// Enough policy for the check: db_ro agrees, db_rw lacks a resource, ssh
	// grants more than listed, the rest are unreferenced.
	return tsapi.Policy{
		Groups:   map[string][]string{"group:sre": {"carol@example.com"}},
		Postures: map[string]tsapi.Posture{"posture:jit_db_ro": {"custom:jit_db_ro == true"}, "posture:jit_db_rw": {"custom:jit_db_rw == true"}, "posture:jit_ssh": {"custom:jit_ssh == true"}},
		Grants: []tsapi.Grant{
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:mysql-prod", "svc:postgres-analytics", "svc:mysql-staging"}, SrcPosture: []string{"posture:jit_db_ro"}},
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:mysql-prod"}, SrcPosture: []string{"posture:jit_db_rw"}},
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:ssh-bastion", "svc:ssh-ops-1", "svc:ssh-ops-2"}, SrcPosture: []string{"posture:jit_ssh"}},
		},
	}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8099", "address to serve on")
	envFile := flag.String("env-file", "", "credentials file for the Tailscale page; a temp file with made-up values if empty, so point it at a missing file to see the failure state")
	demo := flag.Bool("demo", false, "use the demo cast (Maya, Sam, Priya, Leo), demo flows and two weeks of history, for screenshots")
	baseURL := flag.String("base-url", "", "base URL used in approval links (default http://<listen>)")
	defaultWho := flag.String("default", "", "person to assume when a request has no who cookie (e.g. so an MCP client can talk to the preview)")
	slackConnected := flag.Bool("slack", true, "start with a made-up Slack workspace connected (false: the Slack page shows the setup steps)")
	tsMode := flag.String("tailscale", "page", "how the Tailscale API credential is set up: page (saved on the Tailscale page), env (in the env file), off (the page shows the setup steps); a client secret starting with tskey-client-wrong is refused")
	oktaMode := flag.String("okta", "page", "how the made-up Okta org is set up: page (credentials saved on the Okta page), env (set in the env file, with allowlists), off (the Okta page shows the setup steps), failing (saved on the page, but Okta refuses them)")
	googleMode := flag.String("google", "page", "how the made-up Google account is set up: page (key saved on the Google Groups page), env (key in the env file), off (the page shows the setup steps), failing (saved on the page, but the service account has lost its role); a pasted key for an account starting with norole@ is refused")
	flag.Parse()
	admins := []jit.Principal{"root@example.com"}
	if *demo {
		people, admins = demoPeople, demoAdmins
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	dir, err := os.MkdirTemp("", "jitd-preview-")
	if err != nil {
		log.Error("tempdir", "err", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)
	st, err := jit.Open(filepath.Join(dir, "jit.db"))
	if err != nil {
		log.Error("store", "err", err)
		os.Exit(1)
	}
	ts := &fakeTS{attrs: map[string]time.Time{}}
	svc := &jit.Service{Store: st, TS: ts, Log: log, Admins: admins}
	// A made-up Okta org: everyone in the cast has a user.
	of := okta.NewFake()
	for name, p := range people {
		of.AddUser("00u"+name, p.Login)
	}
	of.AddGroup("00gAWSPRODADMIN01", "AWS-Prod-Admin", "")
	of.AddGroup("00gAWSPRODREAD002", "AWS-Prod-ReadOnly", "")
	of.AddGroup("00gGRAFANAADMIN3", "Grafana-Admins", "")
	// The Okta page saves to the store like the real one, but whatever is
	// pasted there reaches the made-up org. An address that starts with
	// "wrong" is refused the way Okta refuses a key it does not know, to
	// show what a failed save looks like.
	oktaKey := previewKey()
	oktaEnv := map[string]string{}
	if *oktaMode == "env" {
		oktaEnv = map[string]string{
			"OKTA_ORG_URL": "https://example.okta.com", "OKTA_CLIENT_ID": "0oa1preview0000jitd5d7", "OKTA_PRIVATE_KEY": oktaKey,
			jit.EnvOktaGrantAllowlist: "AWS-Prod-Admin, AWS-Prod-ReadOnly", jit.EnvOktaReadAllowlist: "",
		}
	}
	oktaSetup := &oktasetup.Manager{Store: st, Svc: svc, EnvFile: filepath.Join(dir, "env"), Log: log,
		Env: func() (map[string]string, error) { return oktaEnv, nil },
		Dial: func(vars map[string]string) (okta.Client, error) {
			if strings.Contains(vars["OKTA_ORG_URL"], "//wrong") {
				bad := okta.NewFake()
				bad.Fail["check"] = &okta.TokenError{Status: 401, Code: "invalid_client", Description: "The client_assertion signature is invalid."}
				return bad, nil
			}
			return of, nil
		}}
	oktaSetup.Load()
	oktaClient := &okta.Dynamic{Load: oktaSetup.Vars, New: func(map[string]string) (okta.Client, error) { return of, nil }}
	svc.Okta = oktaClient
	svc.OktaLimits = func() jit.OktaAllowlist {
		vars, err := oktaClient.Vars()
		if err != nil {
			return jit.NoOktaGroups()
		}
		return jit.ParseOktaAllowlist(vars)
	}
	if *oktaMode == "page" || *oktaMode == "failing" {
		if _, err := oktaSetup.Save(context.Background(), jit.Identity{Login: string(admins[0])}, oktasetup.Input{
			OrgURL: "https://example.okta.com", ClientID: "0oa1preview0000jitd5d7", PrivateKey: oktaKey}); err != nil {
			log.Error("preview okta", "err", err)
		}
	}
	// A made-up Google account, set up the same way. A key for a service
	// account whose address starts with "norole@" is refused the way Google
	// refuses one that was never given the Groups Admin role.
	gf := google.NewFake()
	gf.AddGroup("01gcpprodviewers", "gcp-prod-viewers@example.com", false)
	gf.AddGroup("02gcpprodadmins0", "gcp-prod-admins@example.com", false)
	gf.AddGroup("03allengineering", "engineering@example.com", true)
	const googleAccount = "jitd@example-prod.iam.gserviceaccount.com"
	noRole := &google.APIError{Status: 403, Message: "Error(2028): Permission denied for membership resource 'groups/-' (or it may not exist)."}
	googleEnv := map[string]string{}
	if *googleMode == "env" {
		googleEnv = map[string]string{google.EnvKey: google.FakeKey(googleAccount, "example-prod"), google.EnvDomains: "example.com"}
	}
	googleSetup := &googlesetup.Manager{Store: st, Svc: svc, EnvFile: filepath.Join(dir, "env"), Log: log,
		Env: func() (map[string]string, error) { return googleEnv, nil },
		Dial: func(vars map[string]string) (google.Client, error) {
			if key, _ := google.ParseKey(vars[google.EnvKey]); key != nil && strings.HasPrefix(key.Email, "norole@") {
				bad := google.NewFake()
				bad.Fail["check"] = noRole
				return bad, nil
			}
			return gf, nil
		}}
	googleSetup.Load()
	googleClient := &google.Dynamic{Load: googleSetup.Vars, New: func(map[string]string) (google.Client, error) { return gf, nil }}
	svc.Google = googleClient
	svc.GoogleLimits = func() jit.GoogleLimits {
		vars, err := googleClient.Vars()
		if err != nil {
			return jit.NoGoogleGroups()
		}
		return jit.ParseGoogleLimits(vars)
	}
	if *googleMode == "page" || *googleMode == "failing" {
		if _, err := googleSetup.Save(context.Background(), jit.Identity{Login: string(admins[0])}, googlesetup.Input{
			Key: google.FakeKey(googleAccount, "example-prod"), Domains: "example.com", Grant: "*"}); err != nil {
			log.Error("preview google", "err", err)
		}
	}
	svc.PolicyCache = &jit.PolicyCache{TS: ts, TTL: time.Minute, Log: log}

	// A made-up Slack: everyone in the cast has an account, and the bot can
	// post to a few channels. Posts go nowhere.
	base := cmp.Or(*baseURL, "http://"+*listen)
	fs := slack.NewFake()
	for name, p := range people {
		fs.AddUser("U"+strings.ToUpper(name), p.Login, p.DisplayName)
	}
	fs.AddChannel("C0SREONCALL", "sre-oncall", false)
	fs.AddChannel("C0JITAPPROV", "jit-approvals", false)
	fs.AddChannel("G0SECURITY0", "security", true)
	bot := &slackbot.Bot{Svc: svc, Log: log, BaseURL: base, EnvFile: filepath.Join(dir, "env"),
		NewAPI: func(string, string) slack.API { return fs }, Dial: fs.Dial}
	svc.Notify = bot
	bot.Start(context.Background())
	if *slackConnected {
		admin := jit.Identity{Login: string(admins[0])}
		if _, err := bot.Connect(context.Background(), admin, slackbot.ConnectInput{
			BotToken: "xoxb-preview-0000", AppToken: "xapp-preview-0000", AllowedDomains: []string{"example.com"}}); err != nil {
			log.Error("preview slack", "err", err)
		}
	}
	if *demo {
		ts.policy = demoPolicy()
		seedDemo(svc)
	} else {
		seed(svc)
	}

	if *envFile == "" {
		*envFile = filepath.Join(dir, "env")
		if *tsMode == "env" {
			os.WriteFile(*envFile, []byte("TS_OAUTH_CLIENT_ID=preview\nTS_OAUTH_CLIENT_SECRET=preview\n"), 0o600)
		}
	}
	checker := &setup.Checker{
		EnvFile: *envFile, Store: st, Tag: "tag:jit", Log: log,
		Node: func(context.Context) (setup.Node, error) {
			return setup.Node{ID: "nJIT", DNSName: "jit.example.ts.net", Tags: []string{"tag:jit"}}, nil
		},
		NewClient: func(_ context.Context, _ string, vars map[string]string) (tsapi.Client, error) {
			if strings.HasPrefix(vars["TS_OAUTH_CLIENT_SECRET"], "tskey-client-wrong") {
				return refusedTS{ts}, nil
			}
			return ts, nil
		},
	}
	if *tsMode == "page" {
		if _, err := checker.Save(context.Background(), string(admins[0]), setup.Input{ClientID: "kPreview11CNTRL", ClientSecret: "tskey-client-kPreview11CNTRL-madeUpForThePreview"}); err != nil {
			log.Error("preview: saving the Tailscale credential", "err", err)
		}
	}
	checker.Run(context.Background())
	if *oktaMode == "failing" {
		of.Fail["check"] = &okta.APIError{Method: "GET", Path: "/api/v1/groups?limit=1", Status: 403, Code: "E0000006", Summary: "You do not have permission to perform the requested action"}
		svc.OktaCheckNow(context.Background())
	}
	if *googleMode == "failing" {
		gf.Fail["check"] = noRole
		svc.GoogleCheckNow(context.Background())
	}

	h := &jithttp.Server{
		Svc: svc, TS: ts, Setup: checker, Slack: bot, Okta: oktaSetup, Google: googleSetup, JITTag: "tag:jit", BaseURL: base, Log: log,
		Resolver: jit.ResolverFunc(func(ctx context.Context, r *http.Request) (jit.Identity, error) {
			c, _ := r.Cookie("who")
			if c != nil {
				if id, ok := people[c.Value]; ok {
					return id, nil
				}
			}
			if id, ok := people[*defaultWho]; ok {
				return id, nil
			}
			return jit.Identity{}, &jit.Error{Code: "identity_unavailable", Status: 401, Message: "pick who you are at /as/alice (alice, bob, carol, dave, root)"}
		}),
	}
	h.MCP = (&jitmcp.Server{Svc: svc, Resolver: h.Resolver, BaseURL: base, Version: "preview", Log: log}).Handler()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /as/{who}", func(w http.ResponseWriter, r *http.Request) {
		who := r.PathValue("who")
		if _, ok := people[who]; !ok {
			http.Error(w, "unknown person", 404)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "who", Value: who, Path: "/"})
		next := r.URL.Query().Get("next")
		if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			next = "/"
		}
		http.Redirect(w, r, next, http.StatusFound)
	})
	// /mcp-host plays an MCP Apps host against this preview's /mcp, to see
	// the ui://jit/app view in a browser without a host that renders it.
	mux.HandleFunc("GET /mcp-host", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, mcpHostPage)
	})
	mux.Handle("/", h.Handler())
	names := make([]string, 0, len(people))
	for n := range people {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Printf("preview at http://%s/ — pick a person: /as/{%s}\n", *listen, strings.Join(names, ","))
	go func() {
		for range time.Tick(5 * time.Second) {
			svc.ExpireDue()
		}
	}()
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// seed fills the store with flows and requests that exercise every role.
// previewKey makes a private key for the made-up Okta service app, so the
// Okta page has a real fingerprint to show.
func previewKey() string {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func seed(svc *jit.Service) {
	ctx := context.Background()
	must := func(w *jit.Workflow, err error) *jit.Workflow {
		if err != nil {
			panic(err)
		}
		return w
	}
	dbRO := must(svc.CreateWorkflow(jit.Workflow{
		Name: "Database access (read-only)", Description: "Read-only queries on all databases", Attribute: "db_ro",
		Resources:  []jit.Resource{{Name: "svc:mysql-prod", Description: "Production MySQL, orders and customers (us-east-1)"}, {Name: "svc:postgres-analytics", Description: "Analytics Postgres, read replica"}, {Name: "svc:mysql-staging", Description: "Staging MySQL"}},
		Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"bob@example.com", "group:sre"},
		MaxDuration: jit.Duration(4 * time.Hour), DefaultDuration: jit.Duration(time.Hour),
	}))
	dbRW := must(svc.CreateWorkflow(jit.Workflow{
		Name: "Database access (read-write)", Description: "Read and write on all databases; two approvals", Attribute: "db_rw",
		Resources:  []jit.Resource{{Name: "svc:mysql-prod", Description: "Production MySQL, orders and customers (us-east-1)"}, {Name: "svc:postgres-analytics", Description: "Analytics Postgres"}},
		Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"bob@example.com", "group:sre", "root@example.com"},
		ApprovalsRequired: 2, MaxDuration: jit.Duration(time.Hour),
	}))
	ssh := must(svc.CreateWorkflow(jit.Workflow{
		Name: "SSH access", Description: "Shell, exec and SFTP on the bastion hosts", Attribute: "ssh",
		Resources:  []jit.Resource{{Name: "svc:ssh-bastion", Description: "Jump host, eu-west-1"}, {Name: "svc:ssh-ops-1", Description: "Ops box (cron, backups)"}},
		Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"autogroup:member"},
		AllowSelfApproval: true, MaxDuration: jit.Duration(8 * time.Hour), DefaultDuration: jit.Duration(2 * time.Hour),
	}))

	var aws *jit.Workflow // only with Okta set up
	if svc.OktaEnabled() {
		aws = must(svc.CreateWorkflow(jit.Workflow{
			Name: "AWS production admin", Description: "Okta group membership: AdministratorAccess in the prod AWS account via SSO",
			OktaGroups: []jit.OktaGroup{{Name: "AWS-Prod-Admin"}},
			Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"bob@example.com", "group:sre"},
			MaxDuration: jit.Duration(4 * time.Hour), DefaultDuration: jit.Duration(time.Hour),
		}))
	}

	// More flows, so the request picker is tested with a realistic number.
	more := []jit.Workflow{
		{Name: "Analytics warehouse (read-only)", Description: "Query the analytics Postgres; SELECT only", Attribute: "analytics_ro", Resources: []jit.Resource{{Name: "svc:postgres-analytics", Description: "Analytics Postgres, read replica"}}, MaxDuration: jit.Duration(8 * time.Hour), DefaultDuration: jit.Duration(2 * time.Hour), Approvers: []jit.Principal{"group:sre"}},
		{Name: "Staging database (read-write)", Description: "Full access to the staging MySQL for testing migrations", Attribute: "staging_rw", Resources: []jit.Resource{{Name: "svc:mysql-staging", Description: "Staging MySQL"}}, MaxDuration: jit.Duration(4 * time.Hour), DefaultDuration: jit.Duration(time.Hour), Approvers: []jit.Principal{"autogroup:member"}, AllowSelfApproval: true},
		{Name: "Production SSH (break-glass)", Description: "Root shell on production hosts; two approvals, keep it short", Attribute: "prod_ssh", Resources: []jit.Resource{{Name: "tag:prod", Description: "All production hosts"}}, MaxDuration: jit.Duration(time.Hour), DefaultDuration: jit.Duration(30 * time.Minute), Approvers: []jit.Principal{"group:sre", "root@example.com"}, ApprovalsRequired: 2},
		{Name: "Grafana editor", Description: "Edit dashboards in Grafana; granted at once, still time-limited", Attribute: "grafana_edit", Resources: []jit.Resource{{Name: "svc:grafana", Description: "Grafana"}}, MaxDuration: jit.Duration(8 * time.Hour), DefaultDuration: jit.Duration(2 * time.Hour), AutoApprove: true},
		{Name: "Bastion SSH", Description: "Shell on the bastion for jump access; no sudo", Attribute: "bastion_ssh", Resources: []jit.Resource{{Name: "svc:ssh-bastion", Description: "Jump host, eu-west-1"}}, MaxDuration: jit.Duration(12 * time.Hour), DefaultDuration: jit.Duration(8 * time.Hour), Approvers: []jit.Principal{"autogroup:member"}, AllowSelfApproval: true},
		{Name: "Billing database (read-only)", Description: "Read-only on the billing MySQL for finance reports", Attribute: "billing_ro", Resources: []jit.Resource{{Name: "svc:mysql-billing", Description: "Billing MySQL (PCI scope)"}}, MaxDuration: jit.Duration(2 * time.Hour), DefaultDuration: jit.Duration(time.Hour), Approvers: []jit.Principal{"bob@example.com"}},
	}
	for _, w := range more {
		w.Requesters = []jit.Principal{"autogroup:member"}
		must(svc.CreateWorkflow(w))
	}

	submit := func(who string, wf *jit.Workflow, dur time.Duration, reason string) *jit.AccessRequest {
		r, err := svc.Submit(ctx, people[who], jit.NewRequest{WorkflowID: wf.ID, Duration: jit.Duration(dur), Reason: reason})
		if err != nil {
			panic(err)
		}
		return r
	}
	// Dave has AWS admin through Okta, approved by bob.
	if aws != nil {
		r := submit("dave", aws, time.Hour, "INC-4821: scale the prod RDS instance")
		if _, err := svc.Approve(ctx, people["bob"], r.ID, "go ahead"); err != nil {
			panic(err)
		}
	}
	// Alice has SSH running (self-approved), waits on bob for read-only DB.
	r := submit("alice", ssh, 2*time.Hour, "Rotate the log shipper config on the bastion")
	svc.Approve(ctx, people["alice"], r.ID, "")
	submit("alice", dbRO, time.Hour, "Investigate slow queries reported in INC-4821")
	// Dave wants read-write; carol already voted, one more needed.
	r = submit("dave", dbRW, 30*time.Minute, "Backfill the orders table after the failed migration")
	svc.Approve(ctx, people["carol"], r.ID, "looks right")
	// Bob's own history: a revoked SSH session and a declined request.
	r = submit("bob", ssh, time.Hour, "Check disk usage on ops-1")
	svc.Approve(ctx, people["bob"], r.ID, "")
	svc.Revoke(ctx, people["bob"], r.ID, "done early")
	r = submit("bob", dbRW, time.Hour, "Fix a typo in a product name")
	svc.Decline(ctx, people["root"], r.ID, "Use the admin tool for that, no raw SQL needed")
}

//go:embed mcphost.html
var mcpHostPage string
