package jithttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// refusedTS answers like Tailscale does to a credential it does not know.
type refusedTS struct{ tsapi.Client }

var errRefused = &tsapi.APIError{Method: "GET", Path: "/api/v2/tailnet/-/acl", Status: 401, Body: `{"message":"API token invalid"}`}

func (refusedTS) GetPolicy(context.Context) (tsapi.Policy, error) { return tsapi.Policy{}, errRefused }
func (refusedTS) GetAttributes(context.Context, string) (tsapi.Attributes, error) {
	return tsapi.Attributes{}, errRefused
}

// newTailscaleServer is a server whose Tailscale credential can be pasted
// on the page. Tailscale refuses the secret "tskey-client-wrong".
func newTailscaleServer(t *testing.T, envFile string) (*httptest.Server, *Server) {
	t.Helper()
	for _, k := range tsapi.CredentialVars {
		t.Setenv(k, "")
	}
	srv, _, h := newTestServerWith(t, func(s *Server) {
		s.Setup = &setup.Checker{
			EnvFile: envFile, Store: s.Svc.Store, Tag: "tag:jit", Target: &tsapi.Switchable{}, Log: s.Log,
			Node: func(context.Context) (setup.Node, error) {
				return setup.Node{ID: "nJIT", Tags: []string{"tag:jit"}}, nil
			},
			NewClient: func(_ context.Context, _ string, vars map[string]string) (tsapi.Client, error) {
				if vars["TS_OAUTH_CLIENT_SECRET"] == "tskey-client-wrong" {
					return refusedTS{s.TS}, nil
				}
				return s.TS, nil
			},
		}
	})
	return srv, h
}

// The Integrations section: one sidebar entry for admins, a tab per
// service, and the old addresses still lead somewhere.
func TestIntegrationsTabs(t *testing.T) {
	srv, _ := newTailscaleServer(t, filepath.Join(t.TempDir(), "env"))

	_, home := getPage(t, srv, "root", "/")
	if !strings.Contains(home, `<a href="/admin/integrations" >Integrations`) {
		t.Error("the admin's sidebar has no Integrations entry")
	}
	for _, old := range []string{`href="/admin/setup"`, `href="/admin/slack"`, `href="/admin/okta"`, `class="tabs"`} {
		if strings.Contains(home, old) {
			t.Errorf("the dashboard still has %s", old)
		}
	}
	if _, body := getPage(t, srv, "alice", "/"); strings.Contains(body, "/admin/integrations") {
		t.Error("a non-admin sees Integrations")
	}

	code, body := getPage(t, srv, "root", "/admin/integrations/tailscale")
	if code != 200 {
		t.Fatalf("the Tailscale tab = %d", code)
	}
	for _, want := range []string{
		`<a href="/admin/integrations" class="on">Integrations`, // the sidebar entry is lit
		`<nav class="tabs"`,
		`<a href="/admin/integrations/tailscale" class="on">Tailscale`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the Tailscale tab lacks %q", want)
		}
	}
	if code, _ := getPage(t, srv, "alice", "/admin/integrations/tailscale"); code != 403 {
		t.Errorf("the Tailscale tab for a non-admin = %d, want 403", code)
	}

	// No placeholders: a tab is there only when its page is.
	if strings.Contains(body, "<em>soon</em>") || strings.Contains(body, `href="/admin/integrations/google"`) {
		t.Error("the tab strip has a tab with no page behind it")
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for from, to := range map[string]string{
		"/admin/integrations": "/admin/integrations/tailscale",
		"/admin/setup":        "/admin/integrations/tailscale",
		"/admin/slack":        "/admin/integrations/slack",
		"/admin/okta":         "/admin/integrations/okta",
	} {
		req, _ := http.NewRequest("GET", srv.URL+from, nil)
		req.Header.Set("X-Test-User", "root")
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 3 || resp.Header.Get("Location") != to {
			t.Errorf("%s = %d to %q, want a redirect to %s", from, resp.StatusCode, resp.Header.Get("Location"), to)
		}
	}
}

// The Tailscale credential is pasted on the page: admins only, tried
// before it is saved, and never shown again.
func TestTailscaleCredentialOnThePage(t *testing.T) {
	srv, h := newTailscaleServer(t, filepath.Join(t.TempDir(), "env"))
	const secret = "tskey-client-kTEST-hunter2value"

	_, body := getPage(t, srv, "root", "/admin/integrations/tailscale")
	for _, want := range []string{"not set up", "Connect Tailscale", "trust-credentials", `data-form="ts-save"`, `name="client_secret"`, `name="api_key"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page before set-up lacks %q", want)
		}
	}

	good := setup.Input{ClientID: "kTEST", ClientSecret: secret}
	for _, method := range []string{"PUT", "DELETE"} {
		if code := call(t, srv, "alice", method, "/v1/setup/credentials", good, nil); code != 403 {
			t.Errorf("%s by a non-admin = %d, want 403", method, code)
		}
	}
	if got := h.Setup.Run(context.Background()).Credentials; got.Source != "" || got.Kind != "" {
		t.Fatalf("a non-admin set the credential: %+v", got)
	}

	// One Tailscale refuses: said so, nothing kept.
	var e apiErr
	if code := call(t, srv, "root", "PUT", "/v1/setup/credentials", setup.Input{ClientID: "kTEST", ClientSecret: "tskey-client-wrong"}, &e); code != 400 {
		t.Fatalf("a refused credential = %d, want 400", code)
	}
	if !strings.Contains(e.Error.Message, "Policy file read") || strings.Contains(e.Error.Message, "tskey-client-wrong") {
		t.Errorf("message = %q", e.Error.Message)
	}
	if _, body := getPage(t, srv, "root", "/admin/integrations/tailscale"); !strings.Contains(body, "Connect Tailscale") {
		t.Error("a refused credential changed the page")
	}

	var res setup.Result
	if code := call(t, srv, "root", "PUT", "/v1/setup/credentials", good, &res); code != 200 || !res.OK || res.Credentials.Source != "ui" {
		t.Fatalf("saving = %d, %+v", code, res)
	}
	_, body = getPage(t, srv, "root", "/admin/integrations/tailscale")
	for _, want := range []string{"working", "Everything works", "Replace the credential", "kTEST", "root@example.com", `id="tsremove"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page after saving lacks %q", want)
		}
	}
	if strings.Contains(body, "Connect Tailscale") {
		t.Error("the page still shows the first-time steps")
	}
	for _, where := range []string{body, httpGet(t, srv, "root", "/v1/setup")} {
		if strings.Contains(where, "hunter2value") {
			t.Fatal("the secret is shown")
		}
	}

	var after setup.Result
	if code := call(t, srv, "root", "DELETE", "/v1/setup/credentials", nil, &after); code != 200 || after.OK || after.Credentials.Source != "" {
		t.Fatalf("removing = %d, %+v", code, after)
	}
	if _, body := getPage(t, srv, "root", "/admin/integrations/tailscale"); !strings.Contains(body, "Connect Tailscale") {
		t.Error("the page after removing does not offer the steps")
	}
}

// A credential in the env file wins: the page says so and offers no form.
func TestTailscaleCredentialFromTheFile(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "env")
	os.WriteFile(envFile, []byte("TS_OAUTH_CLIENT_ID=id\nTS_OAUTH_CLIENT_SECRET=hunter2value\n"), 0o600)
	srv, _ := newTailscaleServer(t, envFile)

	var e apiErr
	if code := call(t, srv, "root", "PUT", "/v1/setup/credentials", setup.Input{ClientID: "kTEST", ClientSecret: "tskey-client-other"}, &e); code != 409 {
		t.Fatalf("saving over the file = %d (%s), want 409", code, e.Error.Message)
	}
	_, body := getPage(t, srv, "root", "/admin/integrations/tailscale")
	for _, want := range []string{"Everything works", "Set up outside this page", envFile} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, not := range []string{`data-form="ts-save"`, "hunter2value", `id="tsremove"`} {
		if strings.Contains(body, not) {
			t.Errorf("the page has %q", not)
		}
	}
}
