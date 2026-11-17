package oktasetup

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

const secretKey = "-----BEGIN PRIVATE KEY-----\nSECRETSECRETSECRET\n-----END PRIVATE KEY-----"

var root = jit.Identity{Login: "root@example.com"}

// env is a Manager wired the way main.go wires it, with a made-up Okta: an
// address that starts with "wrong" is one whose credentials Okta refuses.
type env struct {
	m    *Manager
	svc  *jit.Service
	st   *jit.Store
	vars map[string]string // what the environment and the env file set
	err  error             // the env file cannot be read
	okta *okta.Fake
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := jit.Open(filepath.Join(t.TempDir(), "jit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{st: st, vars: map[string]string{}, okta: okta.NewFake()}
	e.svc = &jit.Service{Store: st, Log: log}
	e.m = e.manager()
	return e
}

// manager returns a new Manager on the same store, as after a restart.
func (e *env) manager() *Manager {
	m := &Manager{Store: e.st, Svc: e.svc, EnvFile: "/etc/jitd/env", Log: e.svc.Log,
		Env: func() (map[string]string, error) { return e.vars, e.err },
		Dial: func(vars map[string]string) (okta.Client, error) {
			if strings.Contains(vars["OKTA_ORG_URL"], "//wrong") {
				f := okta.NewFake()
				f.Fail["check"] = &okta.TokenError{Status: 401, Code: "invalid_client", Description: "The client_assertion signature is invalid."}
				return f, nil
			}
			return e.okta, nil
		}}
	client := &okta.Dynamic{Load: m.Vars, New: func(map[string]string) (okta.Client, error) { return e.okta, nil }}
	e.svc.Okta = client
	e.svc.OktaLimits = func() jit.OktaAllowlist {
		vars, err := client.Vars()
		if err != nil {
			return jit.NoOktaGroups()
		}
		return jit.ParseOktaAllowlist(vars)
	}
	return m
}

func (e *env) stored(t *testing.T) (okta.Settings, bool) {
	t.Helper()
	var s okta.Settings
	found, err := e.st.GetSetting(settingKey, &s)
	if err != nil {
		t.Fatal(err)
	}
	return s, found
}

func code(err error) string {
	var je *jit.Error
	if errors.As(err, &je) {
		return je.Code
	}
	return ""
}

// Save signs in to Okta first and stores nothing that Okta refused.
func TestSaveTestsFirst(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if st := e.m.Status(); st.Configured() || st.Enabled || e.svc.OktaEnabled() {
		t.Fatalf("set up before anything was saved: %+v", st)
	}

	_, err := e.m.Save(ctx, root, Input{OrgURL: "wrong.okta.com", ClientID: "0oa1", PrivateKey: secretKey})
	if code(err) != "bad_request" || !strings.Contains(err.Error(), "Nothing was saved") || !strings.Contains(err.Error(), "client ID and private key") {
		t.Fatalf("refused credentials: err = %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("the error quotes the key: %v", err)
	}
	if _, found := e.stored(t); found || e.m.Status().Configured() || e.svc.OktaEnabled() {
		t.Fatal("credentials Okta refused were stored")
	}

	st, err := e.m.Save(ctx, root, Input{OrgURL: " acme.okta.com/app/UserHome ", ClientID: " 0oa1 ", PrivateKey: secretKey + "\n", PrivateKeyID: "kid1"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != SourceUI || !st.Working() || st.Auth != AuthServiceApp || st.OrgURL != "https://acme.okta.com" || st.ClientID != "0oa1" ||
		st.KeyID != "kid1" || st.SavedBy != "root@example.com" || st.SavedAt.IsZero() {
		t.Errorf("status after saving = %+v", st)
	}
	if !e.svc.OktaEnabled() {
		t.Error("saved, but the service has no Okta")
	}
	if s, found := e.stored(t); !found || s.PrivateKey != secretKey || s.OrgURL != "https://acme.okta.com" {
		t.Errorf("stored = %+v, %v", s, found)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), "SECRET") {
		t.Errorf("the status carries the key: %s", b)
	}

	// A replacement Okta refuses leaves the working ones in place.
	if _, err := e.m.Save(ctx, root, Input{OrgURL: "wrong.okta.com", APIToken: "00secrettoken1234"}); code(err) != "bad_request" {
		t.Fatalf("refused replacement: err = %v", err)
	}
	if s, _ := e.stored(t); s.OrgURL != "https://acme.okta.com" || !e.m.Status().Working() {
		t.Errorf("a refused replacement changed what is stored: %+v", s)
	}

	// An API token instead: only its last characters are ever shown.
	st, err = e.m.Save(ctx, root, Input{OrgURL: "https://acme.okta.com", APIToken: "00secrettoken1234"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Auth != AuthAPIToken || st.TokenHint != "…1234" || st.ClientID != "" || st.KeyFingerprint != "" {
		t.Errorf("status with a token = %+v", st)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), "secrettoken") {
		t.Errorf("the status carries the token: %s", b)
	}

	// After a restart they are still there.
	m2 := e.manager()
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if st := m2.Status(); st.Source != SourceUI || st.Auth != AuthAPIToken || !e.svc.OktaEnabled() {
		t.Errorf("status after a restart = %+v", st)
	}
}

func TestSaveRefusesHalfFilledForms(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name string
		in   Input
		want string
	}{
		{"nothing", Input{}, "Okta address"},
		{"no credential", Input{OrgURL: "acme.okta.com"}, "client ID"},
		{"no key", Input{OrgURL: "acme.okta.com", ClientID: "0oa1"}, "private key"},
		{"no client", Input{OrgURL: "acme.okta.com", PrivateKey: secretKey}, "client ID"},
		{"both", Input{OrgURL: "acme.okta.com", ClientID: "0oa1", PrivateKey: secretKey, APIToken: "t"}, "not both"},
	} {
		if _, err := e.m.Save(t.Context(), root, tc.in); code(err) != "bad_request" || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q in it", tc.name, err, tc.want)
		}
	}
	if _, found := e.stored(t); found {
		t.Error("a half-filled form was stored")
	}
}

// Credentials in the environment or the env file win over the saved ones,
// and the page cannot change them. The allowlists always come from outside.
func TestEnvWins(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.vars = map[string]string{jit.EnvOktaGrantAllowlist: "AWS-Prod-Admin"}
	if _, err := e.m.Save(ctx, root, Input{OrgURL: "page.okta.com", APIToken: "00pagetoken00001"}); err != nil {
		t.Fatal(err)
	}
	vars, err := e.m.Vars()
	if err != nil || vars["OKTA_ORG_URL"] != "https://page.okta.com" || vars[jit.EnvOktaGrantAllowlist] != "AWS-Prod-Admin" {
		t.Fatalf("vars with saved credentials = %v, %v", vars, err)
	}
	if st := e.m.Status(); st.Source != SourceUI || len(st.GrantAllowlist) != 1 || st.GrantAllowlist[0] != "AWS-Prod-Admin" || len(st.ReadAllowlist) != 1 || st.ReadAllowlist[0] != "*" {
		t.Errorf("status = %+v", st)
	}

	e.vars = map[string]string{"OKTA_ORG_URL": "https://env.okta.com", "OKTA_API_TOKEN": "00envtoken000002"}
	vars, err = e.m.Vars()
	if err != nil || vars["OKTA_ORG_URL"] != "https://env.okta.com" || vars["OKTA_API_TOKEN"] != "00envtoken000002" {
		t.Fatalf("vars with the env set = %v, %v", vars, err)
	}
	st := e.m.Status()
	if st.Source != SourceEnv || !st.Shadowed || st.OrgURL != "https://env.okta.com" || st.TokenHint != "…0002" || st.SavedBy != "" {
		t.Errorf("status with the env set = %+v", st)
	}
	if _, err := e.m.Save(ctx, root, Input{OrgURL: "other.okta.com", APIToken: "00othertoken0003"}); code(err) != "conflict" {
		t.Errorf("saving over the env: err = %v", err)
	}
	if s, _ := e.stored(t); s.OrgURL != "https://page.okta.com" {
		t.Errorf("stored = %+v", s)
	}

	// The saved ones can still be removed, and come back into force if the
	// env ones go first.
	e.vars = map[string]string{}
	if st := e.m.Status(); st.Source != SourceUI || st.OrgURL != "https://page.okta.com" {
		t.Errorf("status with the env cleared = %+v", st)
	}
	e.vars = map[string]string{"OKTA_ORG_URL": "https://env.okta.com", "OKTA_API_TOKEN": "00envtoken000002"}
	if st, err := e.m.Remove(ctx, root, false); err != nil || st.Source != SourceEnv || st.Shadowed {
		t.Errorf("removing the shadowed ones: %+v, %v", st, err)
	}
	if _, found := e.stored(t); found {
		t.Error("still stored after Remove")
	}

	// An env file that cannot be read: say so, and keep the page out of it.
	e.err = errors.New("open /etc/jitd/env: permission denied")
	if st := e.m.Status(); st.Source != SourceEnv || !strings.Contains(st.Error, "permission denied") {
		t.Errorf("status with an unreadable env file = %+v", st)
	}
}

func TestRemove(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if st, err := e.m.Remove(ctx, root, false); err != nil || st.Configured() {
		t.Fatalf("removing nothing: %+v, %v", st, err)
	}
	if _, err := e.m.Save(ctx, root, Input{OrgURL: "acme.okta.com", ClientID: "0oa1", PrivateKey: secretKey}); err != nil {
		t.Fatal(err)
	}
	st, err := e.m.Remove(ctx, root, false)
	if err != nil || st.Configured() || st.Enabled || e.svc.OktaEnabled() {
		t.Fatalf("after Remove: %+v, %v", st, err)
	}
	if _, found := e.stored(t); found {
		t.Error("still stored after Remove")
	}
	if m2 := e.manager(); m2.Load() != nil || m2.Status().Configured() {
		t.Error("back after a restart")
	}
}
