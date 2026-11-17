package jithttp

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/googlesetup"
	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

const (
	googleAccount = "jitd@acme-prod.iam.gserviceaccount.com"
	googleAdmins  = "01ggadmin"
	googleAdminsA = "aws-admin@example.com"
)

// newGoogleServer is a test server with the Google page, wired as main.go
// wires it, and a made-up Google: a key for an account that starts with
// "norole@" is one whose service account has no admin role. env is what
// the environment and env file set.
func newGoogleServer(t *testing.T, env map[string]string) (*httptest.Server, *Server, *google.Fake) {
	t.Helper()
	gf := google.NewFake()
	gf.AddGroup(googleAdmins, googleAdminsA, false)
	gf.AddGroup("02ggdyn", "everyone@example.com", true)
	srv, _, h := newTestServerWith(t, func(s *Server) {
		m := &googlesetup.Manager{Store: s.Svc.Store, Svc: s.Svc, EnvFile: "/etc/jitd/env", Log: s.Log,
			Env: func() (map[string]string, error) { return env, nil },
			Dial: func(vars map[string]string) (google.Client, error) {
				if key, _ := google.ParseKey(vars[google.EnvKey]); key != nil && strings.HasPrefix(key.Email, "norole@") {
					f := google.NewFake()
					f.Fail["check"] = &google.APIError{Status: 403, Message: "Error(2028): Permission denied for membership resource"}
					return f, nil
				}
				return gf, nil
			}}
		client := &google.Dynamic{Load: m.Vars, New: func(map[string]string) (google.Client, error) { return gf, nil }}
		s.Google, s.Svc.Google = m, client
		s.Svc.GoogleLimits = func() jit.GoogleLimits {
			vars, err := client.Vars()
			if err != nil {
				return jit.NoGoogleGroups()
			}
			return jit.ParseGoogleLimits(vars)
		}
	})
	return srv, h, gf
}

// keySecret is something only the key file holds.
func keySecret(t *testing.T, key string) string {
	t.Helper()
	_, rest, ok := strings.Cut(key, "-----BEGIN")
	if !ok || len(rest) < 120 {
		t.Fatal("the made-up key has no private key in it")
	}
	return rest[60:100]
}

// Only admins see the Google page or reach its API.
func TestGoogleSetupAdminsOnly(t *testing.T) {
	srv, h, _ := newGoogleServer(t, nil)
	if code, _ := getPage(t, srv, "alice", "/admin/integrations/google"); code != 403 {
		t.Errorf("the page as alice = %d, want 403", code)
	}
	in := map[string]any{"key": google.FakeKey(googleAccount, "acme-prod"), "allowed_domains": "example.com", "grant_allowlist": "*"}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/google", nil}, {"PUT", "/v1/google", in}, {"DELETE", "/v1/google?force=1", nil},
		{"POST", "/v1/google/check", map[string]any{}}, {"POST", "/v1/google/check", map[string]any{"group": googleAdminsA}},
	} {
		var e apiErr
		if code := call(t, srv, "alice", c.method, c.path, c.body, &e); code != 403 {
			t.Errorf("%s %s as alice = %d (%s), want 403", c.method, c.path, code, e.Error.Message)
		}
	}
	if h.Google.Status().Configured() {
		t.Error("a non-admin set Google up")
	}
	if _, body := getPage(t, srv, "root", "/admin/integrations/tailscale"); !strings.Contains(body, `<a href="/admin/integrations/google" >Google Groups</a>`) {
		t.Error("the admin has no Google Groups tab")
	}

	// A build without the page.
	plain, _ := newTestServer(t)
	if code, _ := getPage(t, plain, "root", "/admin/integrations/google"); code != 404 {
		t.Errorf("the page without Google setup = %d, want 404", code)
	}
	if code := call(t, plain, "root", "GET", "/v1/google", nil, nil); code != 404 {
		t.Errorf("GET /v1/google without Google setup = %d, want 404", code)
	}
	if _, body := getPage(t, plain, "root", "/admin/integrations/tailscale"); strings.Contains(body, `href="/admin/integrations/google"`) {
		t.Error("a Google tab for a page that is not there")
	}
}

// The page walks an admin through Google, saves only a key Google takes,
// and never shows it again.
func TestGoogleSetupPage(t *testing.T) {
	srv, h, gf := newGoogleServer(t, nil)
	key := google.FakeKey(googleAccount, "acme-prod")
	secret := keySecret(t, key)

	_, body := getPage(t, srv, "root", "/admin/integrations/google")
	for _, want := range []string{"Connect Google", "Cloud Identity API", "Create service account", "Groups Admin", "Assign service accounts",
		"iam.disableServiceAccountKeyCreation", `data-form="google-save"`, `name="key"`,
		`name="allowed_domains" value="example.com"`, `name="grant_allowlist" value="*"`, "GOOGLE_SERVICE_ACCOUNT_JSON"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page before setup lacks %q", want)
		}
	}
	for _, not := range []string{`id="googleremove"`, `data-form="google-check"`, "coming soon"} {
		if strings.Contains(body, not) {
			t.Errorf("the page before setup has %q", not)
		}
	}

	// A key whose service account has no role, something that is not a
	// key, and a key with nobody allowed: told why, nothing kept.
	var e apiErr
	for name, in := range map[string]map[string]any{
		"no role":    {"key": google.FakeKey("norole@acme-prod.iam.gserviceaccount.com", "acme-prod"), "allowed_domains": "example.com", "grant_allowlist": "*"},
		"not a key":  {"key": "hunter2", "allowed_domains": "example.com", "grant_allowlist": "*"},
		"no domains": {"key": key, "allowed_domains": "", "grant_allowlist": "*"},
	} {
		if code := call(t, srv, "root", "PUT", "/v1/google", in, &e); code != 400 ||
			!strings.Contains(e.Error.Message, "Nothing was saved") || strings.Contains(e.Error.Message, "PRIVATE KEY") || strings.Contains(e.Error.Message, "hunter2") {
			t.Fatalf("%s: saving = %d %q", name, code, e.Error.Message)
		}
		if name == "no role" && !strings.Contains(e.Error.Message, "norole@acme-prod.iam.gserviceaccount.com") {
			t.Errorf("a key without the role: the answer does not name the account to give it to: %q", e.Error.Message)
		}
		if h.Google.Status().Configured() || h.Svc.GoogleEnabled() {
			t.Fatalf("%s: something was saved", name)
		}
	}

	var st googlesetup.Status
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"key": key, "allowed_domains": "Example.com, corp.example", "grant_allowlist": "aws-*@example.com"}, &st); code != 200 {
		t.Fatalf("saving = %d", code)
	}
	if st.Source != googlesetup.SourceUI || !st.Working() || st.SavedBy != "root@example.com" || st.Account != googleAccount || !h.Svc.GoogleEnabled() ||
		strings.Join(st.Domains, " ") != "example.com corp.example" || strings.Join(st.GrantAllowlist, " ") != "aws-*@example.com" {
		t.Errorf("status after saving = %+v", st)
	}

	// Neither the page nor the API gives the key back.
	_, body = getPage(t, srv, "root", "/admin/integrations/google")
	raw := httpGet(t, srv, "root", "/v1/google")
	for name, text := range map[string]string{"page": body, "GET /v1/google": raw} {
		if strings.Contains(text, secret) || strings.Contains(text, "PRIVATE KEY") {
			t.Errorf("the %s carries the key", name)
		}
		if !strings.Contains(text, googleAccount) {
			t.Errorf("the %s does not say which service account is in use", name)
		}
	}
	for _, want := range []string{"Google accepts jitd's key", `data-form="google-check"`, `data-form="google-limits"`, `id="googleremove" data-held="0"`,
		"saved here by root@example.com", `name="allowed_domains" value="example.com, corp.example"`, `name="grant_allowlist" value="aws-*@example.com"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page after setup lacks %q", want)
		}
	}
	if strings.Contains(body, "Connect Google") {
		t.Error("the page after setup still shows the first-time steps")
	}

	// The limits change without pasting the key again.
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"grant_allowlist": "*"}, &st); code != 200 ||
		strings.Join(st.GrantAllowlist, " ") != "*" || strings.Join(st.Domains, " ") != "example.com corp.example" || st.Account != googleAccount || !st.Working() {
		t.Fatalf("changing the groups alone = %d %+v", code, st)
	}

	// Test a group: reads only.
	var out struct {
		Group jit.GoogleGroupCheck `json:"group"`
	}
	if code := call(t, srv, "root", "POST", "/v1/google/check", map[string]any{"group": "AWS-Admin@example.com"}, &out); code != 200 ||
		out.Group.ID != googleAdmins || out.Group.Email != googleAdminsA || !out.Group.Manageable || !out.Group.GrantAllowed {
		t.Errorf("testing a group = %d %+v", code, out.Group)
	}
	if code := call(t, srv, "root", "POST", "/v1/google/check", map[string]any{"group": "everyone@example.com"}, &out); code != 200 || out.Group.Manageable {
		t.Errorf("testing a dynamic group = %d %+v", code, out.Group)
	}
	if code := call(t, srv, "root", "POST", "/v1/google/check", map[string]any{"group": "nope@example.com"}, &e); code != 404 {
		t.Errorf("testing a group Google does not have = %d", code)
	}
	if m := gf.Mutations(); len(m) != 0 {
		t.Errorf("testing groups changed Google: %v", m)
	}

	// The role is taken away: the page says what to fix.
	gf.Fail["check"] = &google.APIError{Status: 403, Message: "Error(2028): Permission denied for membership resource"}
	if code := call(t, srv, "root", "POST", "/v1/google/check", map[string]any{}, nil); code != 200 {
		t.Errorf("check again = %d", code)
	}
	_, body = getPage(t, srv, "root", "/admin/integrations/google")
	if !strings.Contains(body, "does not let the service account do this") || !strings.Contains(body, "Assign service accounts and add "+googleAccount) || strings.Contains(body, "Google accepts jitd's key") {
		t.Error("the page does not say that Google refuses the service account, or how to fix it")
	}
	// Said once there, with the fix; every other page points to it.
	if strings.Contains(body, `id="google-problems"`) || !strings.Contains(body, `<span class="dot bad" title="Google Groups needs a look">`) {
		t.Error("the Google page repeats the problem in the banner, or its tab has no dot")
	}
	if _, home := getPage(t, srv, "root", "/"); !strings.Contains(home, `id="google-problems"`) || !strings.Contains(home, `<a href="/admin/integrations/google">Open the Google Groups page</a>`) ||
		strings.Contains(home, `id="okta-problems"`) {
		t.Error("the banner on other pages does not point to the Google page")
	}
}

// A flow with Google groups, from the form's field to the request page;
// and removing the key while jitd still owes removals takes a second,
// explicit step.
func TestGoogleFlowAndRemoveWhileHeld(t *testing.T) {
	srv, h, gf := newGoogleServer(t, nil)
	_, body := getPage(t, srv, "root", "/admin/workflows/new")
	if strings.Contains(body, `name="google_groups"`) || !strings.Contains(body, `<a href="/admin/integrations/google">Connect Google</a>`) {
		t.Error("the flow form before Google is set up has the field, or does not point to the Google page")
	}
	key := google.FakeKey(googleAccount, "acme-prod")
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"key": key, "allowed_domains": "example.com", "grant_allowlist": "*"}, nil); code != 200 {
		t.Fatalf("saving = %d", code)
	}
	if _, body = getPage(t, srv, "root", "/admin/workflows/new"); !strings.Contains(body, `name="google_groups"`) || !strings.Contains(body, "every 40 minutes") {
		t.Error("the flow form has no Google groups field, or does not warn about Tailscale's sync")
	}

	// As the form sends it: groups by address, no posture attribute.
	var w jit.Workflow
	if code := call(t, srv, "root", "POST", "/v1/workflows", map[string]any{
		"name": "AWS admin", "google_groups": []map[string]string{{"name": "AWS-Admin@example.com"}},
		"requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"}, "max_duration": "1h",
	}, &w); code != 201 || len(w.GoogleGroups) != 1 || w.GoogleGroups[0].ID != googleAdmins || w.GoogleGroups[0].Name != googleAdminsA || w.Attribute != "" {
		t.Fatalf("creating the flow = %d %+v", code, w)
	}
	var e apiErr
	if code := call(t, srv, "root", "POST", "/v1/workflows", map[string]any{
		"name": "Everyone", "google_groups": []map[string]string{{"name": "everyone@example.com"}},
		"requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"}, "max_duration": "1h",
	}, &e); code != 400 || !strings.Contains(e.Error.Message, "dynamic group") {
		t.Errorf("a flow with a dynamic group = %d %q", code, e.Error.Message)
	}
	for _, path := range []string{"/admin/workflows", "/admin/workflows/" + w.ID} {
		if _, body = getPage(t, srv, "root", path); !strings.Contains(body, googleAdminsA) {
			t.Errorf("%s does not name the Google group", path)
		}
	}

	r, err := h.Svc.Submit(t.Context(), people["alice"], jit.NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Svc.Approve(t.Context(), people["bob"], r.ID, ""); err != nil {
		t.Fatal(err)
	}
	if !gf.Member(googleAdmins, "alice@example.com") {
		t.Fatal("alice is not in the group")
	}
	_, body = getPage(t, srv, "root", "/requests/"+r.ID)
	for _, want := range []string{"Active · added to the Google group ", "<li>Google group <b>" + googleAdminsA + "</b></li>", "<dt>Google user</dt><dd>alice@example.com</dd>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the request page lacks %q", want)
		}
	}
	for user, path := range map[string]string{"alice": "/", "root": "/admin/requests"} {
		if _, body = getPage(t, srv, user, path); !strings.Contains(body, "Google: "+googleAdminsA) {
			t.Errorf("%s does not name the Google group on the request", path)
		}
	}

	_, body = getPage(t, srv, "root", "/admin/integrations/google")
	if !strings.Contains(body, `id="googleremove" data-held="1"`) || !strings.Contains(body, "jitd still looks after Google memberships for 1 request") ||
		!strings.Contains(body, "1 approval flow grants Google groups") {
		t.Error("the page does not warn about the membership jitd holds")
	}
	if code := call(t, srv, "root", "DELETE", "/v1/google", nil, &e); code != 409 || !strings.Contains(e.Error.Message, "1 request") {
		t.Fatalf("remove while held = %d %q, want 409", code, e.Error.Message)
	}
	if !h.Svc.GoogleEnabled() {
		t.Fatal("a refused remove turned Google off")
	}
	var st googlesetup.Status
	if code := call(t, srv, "root", "DELETE", "/v1/google?force=1", nil, &st); code != 200 || st.Configured() || st.Held != 1 {
		t.Fatalf("forced remove = %d %+v", code, st)
	}
	if h.Svc.GoogleEnabled() {
		t.Error("Google still on after the key was removed")
	}

	// Set up again: jitd takes alice out when the access is revoked.
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"key": key, "allowed_domains": "example.com", "grant_allowlist": "*"}, nil); code != 200 {
		t.Fatalf("saving again = %d", code)
	}
	if _, err := h.Svc.Revoke(t.Context(), people["bob"], r.ID, ""); err != nil {
		t.Fatal(err)
	}
	if gf.Member(googleAdmins, "alice@example.com") {
		t.Error("alice is still in the group after the revoke")
	}
	if _, body = getPage(t, srv, "root", "/requests/"+r.ID); !strings.Contains(body, "Access removed · Google group membership taken away") {
		t.Error("the request page does not say the Google membership was taken away")
	}
}

// A key from the environment or the env file: the page shows the status
// and the test, the limits stay editable, and the key cannot be changed.
func TestGoogleSetupFromEnv(t *testing.T) {
	key := google.FakeKey(googleAccount, "acme-prod")
	srv, h, _ := newGoogleServer(t, map[string]string{google.EnvKey: key, google.EnvGrantAllowlist: "aws-*@example.com"})
	_, body := getPage(t, srv, "root", "/admin/integrations/google")
	for _, want := range []string{"Key set outside this page", "/etc/jitd/env", googleAccount, `data-form="google-check"`, "aws-*@example.com",
		"GOOGLE_GRANT_ALLOWLIST", "No email domain is allowed"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, not := range []string{keySecret(t, key), `data-form="google-save"`, `id="googleremove"`} {
		if strings.Contains(body, not) {
			t.Errorf("the page has %q", not)
		}
	}
	if raw := httpGet(t, srv, "root", "/v1/google"); strings.Contains(raw, keySecret(t, key)) {
		t.Error("GET /v1/google carries the key")
	}
	var e apiErr
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"key": key, "allowed_domains": "example.com"}, &e); code != 409 {
		t.Errorf("saving a key over the env = %d %q, want 409", code, e.Error.Message)
	}
	// The domains are the page's to set; the groups stay the env's.
	var st googlesetup.Status
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"allowed_domains": "example.com", "grant_allowlist": "*"}, &st); code != 200 ||
		st.Source != googlesetup.SourceEnv || strings.Join(st.Domains, " ") != "example.com" || strings.Join(st.GrantAllowlist, " ") != "aws-*@example.com" || !st.GrantFromEnv || st.DomainsFromEnv {
		t.Errorf("saving the domains beside an env key = %d %+v", code, st)
	}
	if lim := h.Svc.GoogleLimits(); strings.Join(lim.Domains, " ") != "example.com" {
		t.Errorf("limits in force = %+v", lim)
	}
}

// A removal from Google that keeps failing shows to admins on every page
// and on the request itself, beside Okta's when both are stuck.
func TestGoogleProblemsShown(t *testing.T) {
	gf := google.NewFake()
	gf.AddGroup(googleAdmins, googleAdminsA, false)
	now := time.Now().UTC()
	srv, _, h := newTestServerWith(t, func(s *Server) {
		s.Svc.Google = gf
		s.Svc.GoogleLimits = func() jit.GoogleLimits {
			return jit.GoogleLimits{Grant: []string{"*"}, Domains: []string{"example.com"}}
		}
		s.Svc.Now = func() time.Time { return now }
	})
	w, err := h.Svc.CreateWorkflow(jit.Workflow{
		Name: "AWS admin", Attribute: "aws", GoogleGroups: []jit.GroupRef{{Name: googleAdminsA}},
		Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"bob@example.com"},
		MaxDuration: jit.Duration(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.Svc.Submit(t.Context(), people["alice"], jit.NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Svc.Approve(t.Context(), people["bob"], r.ID, ""); err != nil {
		t.Fatal(err)
	}
	gf.Fail["remove:"+googleAdmins] = errors.New("403 forbidden")
	if _, err := h.Svc.Revoke(t.Context(), people["bob"], r.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, body := getPage(t, srv, "alice", "/requests/"+r.ID)
	if !strings.Contains(body, "Google group membership not yet removed, failing since") || !strings.Contains(body, "403 forbidden") {
		t.Errorf("the request page does not say the Google removal is pending")
	}
	now = now.Add(6 * time.Minute)
	h.Svc.ExpireDue()
	_, body = getPage(t, srv, "root", "/")
	for _, want := range []string{`id="google-problems"`, "<b>Google Groups needs a look.</b>", "alice@example.com is still in " + googleAdminsA, "403 forbidden", `href="/requests/` + r.ID + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the admin's page lacks %q", want)
		}
	}
	if strings.Contains(body, "Open the Google Groups page") {
		t.Error("the banner points to a Google page this build does not have")
	}
	if _, body := getPage(t, srv, "alice", "/"); strings.Contains(body, "google-problems") {
		t.Error("a non-admin sees the banner")
	}
	delete(gf.Fail, "remove:"+googleAdmins)
	now = now.Add(time.Minute)
	h.Svc.ExpireDue()
	if _, body := getPage(t, srv, "root", "/"); strings.Contains(body, "google-problems") {
		t.Error("the banner stayed after the removal went through")
	}
}
