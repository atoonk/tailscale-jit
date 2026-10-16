// The preview serves the jitd web UI on localhost with made-up people and
// a fake Tailscale API, for looking at the UI as different roles without a
// tailnet. Pick who you are at /as/<name> (alice, bob, carol, dave, root).
//
//	go run ./jitd/preview -listen 127.0.0.1:8099
package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/jithttp"
	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
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
func (f *fakeTS) GetPolicy(ctx context.Context) (tsapi.Policy, error) {
	if f.policy != nil {
		return *f.policy, nil
	}
	// Enough policy for the check: db_ro agrees, db_rw lacks a resource, ssh
	// grants more than listed, the rest are unreferenced.
	return tsapi.Policy{
		Groups:   map[string][]string{"group:sre": {"carol@example.com"}},
		Postures: map[string][]string{"posture:jit_db_ro": {"custom:jit_db_ro == true"}, "posture:jit_db_rw": {"custom:jit_db_rw == true"}, "posture:jit_ssh": {"custom:jit_ssh == true"}},
		Grants: []tsapi.Grant{
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:mysql-prod", "svc:postgres-analytics", "svc:mysql-staging"}, SrcPosture: []string{"posture:jit_db_ro"}},
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:mysql-prod"}, SrcPosture: []string{"posture:jit_db_rw"}},
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:ssh-bastion", "svc:ssh-ops-1", "svc:ssh-ops-2"}, SrcPosture: []string{"posture:jit_ssh"}},
		},
	}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8099", "address to serve on")
	envFile := flag.String("env-file", "", "credentials file for the Setup page; a temp file with made-up values if empty, so point it at a missing file to see the failure state")
	demo := flag.Bool("demo", false, "use the demo cast (Maya, Sam, Priya, Leo), demo flows and two weeks of history, for screenshots")
	baseURL := flag.String("base-url", "", "base URL used in approval links (default http://<listen>)")
	defaultWho := flag.String("default", "", "person to assume when a request has no who cookie (e.g. so pamagent can talk to the preview)")
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
	svc.PolicyCache = &jit.PolicyCache{TS: ts, TTL: time.Minute, Log: log}
	if *demo {
		ts.policy = demoPolicy()
		seedDemo(svc)
	} else {
		seed(svc)
	}

	if *envFile == "" {
		*envFile = filepath.Join(dir, "env")
		os.WriteFile(*envFile, []byte("TS_OAUTH_CLIENT_ID=preview\nTS_OAUTH_CLIENT_SECRET=preview\n"), 0o600)
	}
	checker := &setup.Checker{
		EnvFile: *envFile, Tag: "tag:jit", Log: log,
		Node: func(context.Context) (setup.Node, error) {
			return setup.Node{ID: "nJIT", DNSName: "jit.example.ts.net", Tags: []string{"tag:jit"}}, nil
		},
		NewClient: func(context.Context, string, map[string]string) (tsapi.Client, error) { return ts, nil },
	}
	checker.Run(context.Background())

	h := &jithttp.Server{
		Svc: svc, TS: ts, Setup: checker, JITTag: "tag:jit", BaseURL: cmp.Or(*baseURL, "http://"+*listen), Log: log,
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

	// More flows, so the request picker is tested with a realistic number.
	more := []jit.Workflow{
		{Name: "Analytics warehouse (read-only)", Description: "Query the analytics Postgres; SELECT only", Attribute: "analytics_ro", Resources: []jit.Resource{{Name: "svc:postgres-analytics", Description: "Analytics Postgres, read replica"}}, MaxDuration: jit.Duration(8 * time.Hour), DefaultDuration: jit.Duration(2 * time.Hour), Approvers: []jit.Principal{"group:sre"}},
		{Name: "Staging database (read-write)", Description: "Full access to the staging MySQL for testing migrations", Attribute: "staging_rw", Resources: []jit.Resource{{Name: "svc:mysql-staging", Description: "Staging MySQL"}}, MaxDuration: jit.Duration(4 * time.Hour), DefaultDuration: jit.Duration(time.Hour), Approvers: []jit.Principal{"autogroup:member"}, AllowSelfApproval: true},
		{Name: "Production SSH (break-glass)", Description: "Root shell on production hosts; two approvals, keep it short", Attribute: "prod_ssh", Resources: []jit.Resource{{Name: "tag:prod", Description: "All production hosts"}}, MaxDuration: jit.Duration(time.Hour), DefaultDuration: jit.Duration(30 * time.Minute), Approvers: []jit.Principal{"group:sre", "root@example.com"}, ApprovalsRequired: 2},
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
