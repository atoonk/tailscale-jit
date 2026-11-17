package jithttp

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
	"github.com/atoonk/tailscale-jit/jitd/internal/oktasetup"
)

const oktaTestKey = "-----BEGIN PRIVATE KEY-----\nSECRETSECRETSECRET\n-----END PRIVATE KEY-----"

// newOktaServer is a test server with the Okta page, wired as main.go wires
// it, and a made-up Okta: an address that starts with "wrong" is one whose
// credentials Okta refuses. env is what the environment and env file set.
func newOktaServer(t *testing.T, env map[string]string) (*httptest.Server, *Server, *okta.Fake) {
	t.Helper()
	of := okta.NewFake()
	srv, _, h := newTestServerWith(t, func(s *Server) {
		m := &oktasetup.Manager{Store: s.Svc.Store, Svc: s.Svc, EnvFile: "/etc/jitd/env", Log: s.Log,
			Env: func() (map[string]string, error) { return env, nil },
			Dial: func(vars map[string]string) (okta.Client, error) {
				if strings.Contains(vars["OKTA_ORG_URL"], "//wrong") {
					f := okta.NewFake()
					f.Fail["check"] = &okta.TokenError{Status: 401, Code: "invalid_client", Description: "The client_assertion signature is invalid."}
					return f, nil
				}
				return of, nil
			}}
		client := &okta.Dynamic{Load: m.Vars, New: func(map[string]string) (okta.Client, error) { return of, nil }}
		s.Okta, s.Svc.Okta = m, client
		s.Svc.OktaLimits = func() jit.OktaAllowlist {
			vars, err := client.Vars()
			if err != nil {
				return jit.NoOktaGroups()
			}
			return jit.ParseOktaAllowlist(vars)
		}
	})
	return srv, h, of
}

// Only admins see the Okta page or reach its API.
func TestOktaSetupAdminsOnly(t *testing.T) {
	srv, h, _ := newOktaServer(t, nil)
	if code, _ := getPage(t, srv, "alice", "/admin/integrations/okta"); code != 403 {
		t.Errorf("the page as alice = %d, want 403", code)
	}
	in := map[string]any{"org_url": "acme.okta.com", "api_token": "00secrettoken1234"}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/okta", nil}, {"PUT", "/v1/okta", in}, {"DELETE", "/v1/okta?force=1", nil},
		{"POST", "/v1/okta/check", map[string]any{}}, {"POST", "/v1/okta/check", map[string]any{"group": "AWS-Prod-Admin"}},
	} {
		var e apiErr
		if code := call(t, srv, "alice", c.method, c.path, c.body, &e); code != 403 {
			t.Errorf("%s %s as alice = %d (%s), want 403", c.method, c.path, code, e.Error.Message)
		}
	}
	if h.Okta.Status().Configured() {
		t.Error("a non-admin set Okta up")
	}
	if _, body := getPage(t, srv, "alice", "/"); strings.Contains(body, `href="/admin/integrations`) {
		t.Error("a non-admin has the Integrations link")
	}
	if _, body := getPage(t, srv, "root", "/admin/integrations/tailscale"); !strings.Contains(body, `<a href="/admin/integrations/okta" >Okta`) {
		t.Error("the admin has no Okta tab")
	}

	// A build without the page.
	plain, _ := newTestServer(t)
	if code, _ := getPage(t, plain, "root", "/admin/integrations/okta"); code != 404 {
		t.Errorf("the page without Okta setup = %d, want 404", code)
	}
	if code := call(t, plain, "root", "GET", "/v1/okta", nil, nil); code != 404 {
		t.Errorf("GET /v1/okta without Okta setup = %d, want 404", code)
	}
	if _, body := getPage(t, plain, "root", "/admin/integrations/tailscale"); strings.Contains(body, `href="/admin/integrations/okta"`) {
		t.Error("an Okta tab for a page that is not there")
	}
}

// The page walks an admin through Okta, saves only credentials Okta takes,
// and never shows them again.
func TestOktaSetupPage(t *testing.T) {
	srv, h, of := newOktaServer(t, nil)
	of.AddGroup("00gADMIN000000000001", "AWS-Prod-Admin", "")
	of.AddGroup("00gSYNCED00000000002", "Engineering", "APP_GROUP")

	_, body := getPage(t, srv, "root", "/admin/integrations/okta")
	for _, want := range []string{"Connect Okta", "API Services", "okta.groups.manage", "Group Administrator", "DPoP",
		`data-form="okta-save"`, `name="private_key"`, `name="api_token"`, "OKTA_GRANT_ALLOWLIST"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page before setup lacks %q", want)
		}
	}
	for _, not := range []string{`id="oktaremove"`, `data-form="okta-check"`} {
		if strings.Contains(body, not) {
			t.Errorf("the page before setup has %q", not)
		}
	}

	// Credentials Okta refuses: told why, nothing kept.
	var e apiErr
	if code := call(t, srv, "root", "PUT", "/v1/okta", map[string]any{"org_url": "wrong.okta.com", "client_id": "0oa1", "private_key": oktaTestKey}, &e); code != 400 ||
		!strings.Contains(e.Error.Message, "Nothing was saved") || strings.Contains(e.Error.Message, "SECRET") {
		t.Fatalf("refused credentials = %d %q", code, e.Error.Message)
	}
	if h.Okta.Status().Configured() || h.Svc.OktaEnabled() {
		t.Fatal("refused credentials were saved")
	}

	var st oktasetup.Status
	if code := call(t, srv, "root", "PUT", "/v1/okta", map[string]any{"org_url": "acme.okta.com", "client_id": "0oa1jitd", "private_key": oktaTestKey}, &st); code != 200 {
		t.Fatalf("saving = %d", code)
	}
	if st.Source != oktasetup.SourceUI || !st.Working() || st.SavedBy != "root@example.com" || !h.Svc.OktaEnabled() {
		t.Errorf("status after saving = %+v", st)
	}

	// Neither the page nor the API gives the key back.
	_, body = getPage(t, srv, "root", "/admin/integrations/okta")
	raw := httpGet(t, srv, "root", "/v1/okta")
	for name, text := range map[string]string{"page": body, "GET /v1/okta": raw} {
		if strings.Contains(text, "SECRET") {
			t.Errorf("the %s carries the private key", name)
		}
		if !strings.Contains(text, "0oa1jitd") || !strings.Contains(text, "https://acme.okta.com") {
			t.Errorf("the %s does not say which app and org are in use", name)
		}
	}
	for _, want := range []string{"Okta accepts jitd's credentials", `data-form="okta-check"`, `id="oktaremove" data-held="0"`, "saved here by root@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page after setup lacks %q", want)
		}
	}
	if strings.Contains(body, "Connect Okta") {
		t.Error("the page after setup still shows the first-time steps")
	}

	// Test a group: reads only.
	var out struct {
		Group jit.OktaGroupCheck `json:"group"`
	}
	if code := call(t, srv, "root", "POST", "/v1/okta/check", map[string]any{"group": "AWS-Prod-Admin"}, &out); code != 200 ||
		out.Group.ID != "00gADMIN000000000001" || !out.Group.Manageable || !out.Group.GrantAllowed {
		t.Errorf("testing a group = %d %+v", code, out.Group)
	}
	if code := call(t, srv, "root", "POST", "/v1/okta/check", map[string]any{"group": "Engineering"}, &out); code != 200 || out.Group.Manageable {
		t.Errorf("testing a group an app fills = %d %+v", code, out.Group)
	}
	if code := call(t, srv, "root", "POST", "/v1/okta/check", map[string]any{"group": "Nope"}, &e); code != 404 {
		t.Errorf("testing a group Okta does not have = %d", code)
	}
	if m := of.Mutations(); len(m) != 0 {
		t.Errorf("testing groups changed Okta: %v", m)
	}

	// Okta stops taking the credentials: the page says what to fix.
	of.Fail["check"] = &okta.APIError{Status: 403, Summary: "You do not have permission to perform the requested action"}
	if code := call(t, srv, "root", "POST", "/v1/okta/check", map[string]any{}, nil); code != 200 {
		t.Errorf("check again = %d", code)
	}
	_, body = getPage(t, srv, "root", "/admin/integrations/okta")
	if !strings.Contains(body, "does not let it look at groups") || !strings.Contains(body, "Admin roles tab") || strings.Contains(body, "Okta accepts jitd's credentials") {
		t.Error("the page does not say that Okta refuses the credentials, or how to fix it")
	}
	// Said once there, with the fix; every other page points to it.
	if strings.Contains(body, `id="okta-problems"`) || !strings.Contains(body, `<span class="dot bad" title="Okta needs a look">`) {
		t.Error("the Okta page repeats the problem in the banner, or its sidebar entry has no dot")
	}
	if _, home := getPage(t, srv, "root", "/"); !strings.Contains(home, `id="okta-problems"`) || !strings.Contains(home, `<a href="/admin/integrations/okta">Open the Okta page</a>`) {
		t.Error("the banner on other pages does not point to the Okta page")
	}
}

// Removing the credentials while jitd still owes removals takes a second,
// explicit step; what it owes stays on record.
func TestOktaSetupRemoveWhileHeld(t *testing.T) {
	const group = "00gADMIN000000000001"
	srv, h, of := newOktaServer(t, nil)
	of.AddUser("00uALICE", "alice@example.com")
	of.AddGroup(group, "AWS-Prod-Admin", "")
	if code := call(t, srv, "root", "PUT", "/v1/okta", map[string]any{"org_url": "acme.okta.com", "api_token": "00secrettoken1234"}, nil); code != 200 {
		t.Fatalf("saving = %d", code)
	}
	w, err := h.Svc.CreateWorkflow(jit.Workflow{
		Name: "AWS admin", OktaGroups: []jit.OktaGroup{{ID: group}},
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
	if !of.Member(group, "00uALICE") {
		t.Fatal("alice is not in the group")
	}

	_, body := getPage(t, srv, "root", "/admin/integrations/okta")
	if !strings.Contains(body, `id="oktaremove" data-held="1"`) || !strings.Contains(body, "jitd still looks after Okta memberships for 1 request") ||
		strings.Contains(body, "secrettoken") || !strings.Contains(body, "…1234") {
		t.Error("the page does not warn about the membership jitd holds, or shows the token")
	}
	var e apiErr
	if code := call(t, srv, "root", "DELETE", "/v1/okta", nil, &e); code != 409 || !strings.Contains(e.Error.Message, "1 request") {
		t.Fatalf("remove while held = %d %q, want 409", code, e.Error.Message)
	}
	if !h.Svc.OktaEnabled() {
		t.Fatal("a refused remove turned Okta off")
	}
	var st oktasetup.Status
	if code := call(t, srv, "root", "DELETE", "/v1/okta?force=1", nil, &st); code != 200 || st.Configured() || st.Held != 1 {
		t.Fatalf("forced remove = %d %+v", code, st)
	}
	if h.Svc.OktaEnabled() {
		t.Error("Okta still on after the credentials were removed")
	}

	// Set up again: jitd takes alice out when the access is revoked.
	if code := call(t, srv, "root", "PUT", "/v1/okta", map[string]any{"org_url": "acme.okta.com", "api_token": "00secrettoken1234"}, nil); code != 200 {
		t.Fatalf("saving again = %d", code)
	}
	if _, err := h.Svc.Revoke(t.Context(), people["bob"], r.ID, ""); err != nil {
		t.Fatal(err)
	}
	if of.Member(group, "00uALICE") {
		t.Error("alice is still in the group after the revoke")
	}
	if st := h.Okta.Status(); st.Held != 0 {
		t.Errorf("held after the revoke = %d", st.Held)
	}
}

// Credentials from the environment or the env file: the page shows the
// status and the test, and no way to change them.
func TestOktaSetupFromEnv(t *testing.T) {
	srv, h, _ := newOktaServer(t, map[string]string{
		"OKTA_ORG_URL": "https://env.okta.com", "OKTA_API_TOKEN": "00envsecrettoken5678",
		jit.EnvOktaGrantAllowlist: "AWS-Prod-Admin",
	})
	_, body := getPage(t, srv, "root", "/admin/integrations/okta")
	for _, want := range []string{"Set up outside this page", "/etc/jitd/env", "https://env.okta.com", "…5678", `data-form="okta-check"`, "AWS-Prod-Admin"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, not := range []string{"envsecrettoken", `data-form="okta-save"`, `id="oktaremove"`} {
		if strings.Contains(body, not) {
			t.Errorf("the page has %q", not)
		}
	}
	if raw := httpGet(t, srv, "root", "/v1/okta"); strings.Contains(raw, "envsecrettoken") {
		t.Error("GET /v1/okta carries the token")
	}
	var e apiErr
	if code := call(t, srv, "root", "PUT", "/v1/okta", map[string]any{"org_url": "acme.okta.com", "api_token": "00secrettoken1234"}, &e); code != 409 {
		t.Errorf("saving over the env = %d %q, want 409", code, e.Error.Message)
	}
	if st := h.Okta.Status(); st.Source != oktasetup.SourceEnv || st.Shadowed {
		t.Errorf("status = %+v", st)
	}
}

// httpGet returns the body of an API answer as text.
func httpGet(t *testing.T, srv *httptest.Server, user, path string) string {
	t.Helper()
	_, body := getPage(t, srv, user, path)
	return body
}
