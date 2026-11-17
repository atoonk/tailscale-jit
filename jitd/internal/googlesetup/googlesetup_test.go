package googlesetup

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

const account = "jitd@proj-1.iam.gserviceaccount.com"

var root = jit.Identity{Login: "root@example.com"}

// env is a Manager wired the way main.go wires it, with a made-up Google:
// a key for an account that starts with "wrong" is one Google refuses.
type env struct {
	m    *Manager
	svc  *jit.Service
	st   *jit.Store
	vars map[string]string // what the environment and the env file set
	err  error             // the env file cannot be read
	g    *google.Fake
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := jit.Open(filepath.Join(t.TempDir(), "jit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{st: st, vars: map[string]string{}, g: google.NewFake()}
	e.svc = &jit.Service{Store: st, Log: log}
	e.m = e.manager()
	return e
}

// manager returns a new Manager on the same store, as after a restart.
func (e *env) manager() *Manager {
	m := &Manager{Store: e.st, Svc: e.svc, EnvFile: "/etc/jitd/env", Log: e.svc.Log,
		Env: func() (map[string]string, error) { return e.vars, e.err },
		Dial: func(vars map[string]string) (google.Client, error) {
			if strings.Contains(vars[google.EnvKey], `"wrong@`) {
				f := google.NewFake()
				f.Fail["check"] = &google.APIError{Status: 403, Message: "Error(2028): Permission denied for resource groups."}
				return f, nil
			}
			return e.g, nil
		}}
	client := &google.Dynamic{Load: m.Vars, New: func(map[string]string) (google.Client, error) { return e.g, nil }}
	e.svc.Google = client
	e.svc.GoogleLimits = func() jit.GoogleLimits {
		vars, err := client.Vars()
		if err != nil {
			return jit.NoGoogleGroups()
		}
		return jit.ParseGoogleLimits(vars)
	}
	return m
}

func (e *env) stored(t *testing.T) (google.Settings, bool) {
	t.Helper()
	var s google.Settings
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

// secret is something only the key file holds.
func secret(key string) string {
	var f map[string]string
	json.Unmarshal([]byte(key), &f)
	return f["private_key"][40:80]
}

// Save tries the key against Google first and stores nothing that Google
// refused.
func TestSaveTestsFirst(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	key := google.FakeKey(account, "proj-1")
	if st := e.m.Status(); st.Configured() || st.Enabled || e.svc.GoogleEnabled() {
		t.Fatalf("set up before anything was saved: %+v", st)
	}

	_, err := e.m.Save(ctx, root, Input{Key: google.FakeKey("wrong@proj-1.iam.gserviceaccount.com", "proj-1"), Domains: "example.com", Grant: "*"})
	if code(err) != "bad_request" || !strings.Contains(err.Error(), "Nothing was saved") || !strings.Contains(err.Error(), "Groups Admin") ||
		!strings.Contains(err.Error(), "wrong@proj-1.iam.gserviceaccount.com") {
		t.Fatalf("refused key: err = %v", err)
	}
	if strings.Contains(err.Error(), secret(key)) {
		t.Errorf("the error quotes the key: %v", err)
	}
	if _, found := e.stored(t); found || e.m.Status().Configured() || e.svc.GoogleEnabled() {
		t.Fatal("a key Google refused was stored")
	}

	st, err := e.m.Save(ctx, root, Input{Key: "\n" + key + "\n", Domains: "Example.com, @corp.example example.com", Grant: "AWS-*@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != SourceUI || !st.Working() || st.Account != account || st.KeyID == "" || st.Project != "proj-1" ||
		!strings.Contains(st.EnableURL, "proj-1") || st.SavedBy != "root@example.com" || st.SavedAt.IsZero() ||
		!slices.Equal(st.Domains, []string{"example.com", "corp.example"}) || !slices.Equal(st.GrantAllowlist, []string{"aws-*@example.com"}) {
		t.Errorf("status after saving = %+v", st)
	}
	if !e.svc.GoogleEnabled() {
		t.Error("saved, but the service has no Google")
	}
	if lim := e.svc.GoogleLimits(); !slices.Equal(lim.Domains, []string{"example.com", "corp.example"}) || !slices.Equal(lim.Grant, []string{"aws-*@example.com"}) {
		t.Errorf("limits in force = %+v", lim)
	}
	if s, found := e.stored(t); !found || s.Key != key {
		t.Errorf("stored = %v", found)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), secret(key)) || strings.Contains(string(b), "PRIVATE KEY") {
		t.Errorf("the status carries the key: %s", b)
	}

	// A replacement Google refuses leaves the working one in place.
	if _, err := e.m.Save(ctx, root, Input{Key: google.FakeKey("wrong@proj-1.iam.gserviceaccount.com", "proj-1"), Domains: "example.com", Grant: "*"}); code(err) != "bad_request" {
		t.Fatalf("refused replacement: err = %v", err)
	}
	if s, _ := e.stored(t); s.Key != key || !e.m.Status().Working() || len(s.Domains) != 2 {
		t.Errorf("a refused replacement changed what is stored")
	}

	// The limits change without the key being pasted again.
	st, err = e.m.Save(ctx, root, Input{Domains: "example.com", Grant: "*"})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := e.stored(t); s.Key != key || !slices.Equal(st.Domains, []string{"example.com"}) || !slices.Equal(st.GrantAllowlist, []string{"*"}) || st.Account != account {
		t.Errorf("after changing the limits only: %+v", st)
	}

	// After a restart it is all still there.
	m2 := e.manager()
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if st := m2.Status(); st.Source != SourceUI || st.Account != account || !e.svc.GoogleEnabled() || !slices.Equal(st.Domains, []string{"example.com"}) {
		t.Errorf("status after a restart = %+v", st)
	}
}

func TestSaveRefusesWhatCannotWork(t *testing.T) {
	e := newEnv(t)
	key := google.FakeKey(account, "proj-1")
	for _, tc := range []struct {
		name string
		in   Input
		want string
	}{
		{"nothing", Input{}, "email domains"},
		{"no key", Input{Domains: "example.com", Grant: "*"}, "JSON key"},
		{"not a key", Input{Key: "-----BEGIN PRIVATE KEY-----", Domains: "example.com", Grant: "*"}, "not a JSON key file"},
		{"a user's credential", Input{Key: `{"type":"authorized_user"}`, Domains: "example.com", Grant: "*"}, "not a service account key"},
		{"no domains", Input{Key: key, Grant: "*"}, "email domains"},
		{"a wildcard domain", Input{Key: key, Domains: "*", Grant: "*"}, "not an email domain"},
		{"an address for a domain", Input{Key: key, Domains: "alice@example.com", Grant: "*"}, "not an email domain"},
		{"no groups", Input{Key: key, Domains: "example.com"}, "which groups"},
	} {
		if _, err := e.m.Save(t.Context(), root, tc.in); code(err) != "bad_request" || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q in it", tc.name, err, tc.want)
		}
	}
	if _, found := e.stored(t); found {
		t.Error("a form that cannot work was stored")
	}
}

// What the environment or the env file sets wins over the page, value by
// value, and the page cannot change it.
func TestEnvWins(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	pageKey := google.FakeKey("page@proj-1.iam.gserviceaccount.com", "proj-1")
	envKey := google.FakeKey("env@proj-2.iam.gserviceaccount.com", "proj-2")
	if _, err := e.m.Save(ctx, root, Input{Key: pageKey, Domains: "example.com", Grant: "*"}); err != nil {
		t.Fatal(err)
	}

	// A list set outside wins, even when it is set to nothing.
	e.vars = map[string]string{google.EnvGrantAllowlist: ""}
	st := e.m.Status()
	if st.Source != SourceUI || !st.GrantFromEnv || st.DomainsFromEnv || len(st.GrantAllowlist) != 0 || !slices.Equal(st.Domains, []string{"example.com"}) {
		t.Errorf("status with the allowlist set outside = %+v", st)
	}
	// The page still saves the rest, and keeps its own list for later.
	if st, err := e.m.Save(ctx, root, Input{Domains: "corp.example", Grant: "ignored@example.com"}); err != nil || len(st.GrantAllowlist) != 0 || !slices.Equal(st.Domains, []string{"corp.example"}) {
		t.Errorf("saving beside it: %+v, %v", st, err)
	}
	if s, _ := e.stored(t); !slices.Equal(s.Grant, []string{"*"}) || s.Key != pageKey {
		t.Errorf("stored allowlist = %v", s.Grant)
	}

	// A key set outside wins.
	e.vars = map[string]string{google.EnvKey: envKey, google.EnvDomains: "env.example"}
	vars, err := e.m.Vars()
	if err != nil || vars[google.EnvKey] != envKey || vars[google.EnvDomains] != "env.example" || vars[google.EnvGrantAllowlist] != "*" {
		t.Fatalf("vars with the env set: %v", err)
	}
	st = e.m.Status()
	if st.Source != SourceEnv || !st.Shadowed || st.Account != "env@proj-2.iam.gserviceaccount.com" || st.SavedBy != "" || !st.DomainsFromEnv ||
		!slices.Equal(st.Domains, []string{"env.example"}) || !slices.Equal(st.GrantAllowlist, []string{"*"}) {
		t.Errorf("status with the env set = %+v", st)
	}
	if _, err := e.m.Save(ctx, root, Input{Key: pageKey, Domains: "example.com", Grant: "*"}); code(err) != "conflict" {
		t.Errorf("saving a key over the env: err = %v", err)
	}
	// With the key outside and nothing saved, the lists can be set here.
	if st, err := e.m.Remove(ctx, root, false); err != nil || st.Source != SourceEnv || st.Shadowed {
		t.Errorf("removing the shadowed key: %+v, %v", st, err)
	}
	if _, found := e.stored(t); found {
		t.Error("still stored after Remove")
	}
	if st, err := e.m.Save(ctx, root, Input{Grant: "aws-*"}); err != nil || st.Source != SourceEnv || !slices.Equal(st.GrantAllowlist, []string{"aws-*"}) {
		t.Errorf("saving the allowlist beside an env key: %+v, %v", st, err)
	}
	if s, _ := e.stored(t); s.Key != "" {
		t.Error("the env key was copied into the database")
	}

	// An env file that cannot be read: say so, and keep the page out of it.
	e.err = errors.New("open /etc/jitd/env: permission denied")
	if st := e.m.Status(); st.Source != SourceEnv || !strings.Contains(st.Error, "permission denied") {
		t.Errorf("status with an unreadable env file = %+v", st)
	}
	if _, err := e.m.Save(ctx, root, Input{Key: pageKey, Domains: "example.com", Grant: "*"}); code(err) != "conflict" {
		t.Errorf("saving with an unreadable env file: err = %v", err)
	}
}

func TestRemove(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if st, err := e.m.Remove(ctx, root, false); err != nil || st.Configured() {
		t.Fatalf("removing nothing: %+v, %v", st, err)
	}
	if _, err := e.m.Save(ctx, root, Input{Key: google.FakeKey(account, "proj-1"), Domains: "example.com", Grant: "*"}); err != nil {
		t.Fatal(err)
	}
	st, err := e.m.Remove(ctx, root, false)
	if err != nil || st.Configured() || st.Enabled || e.svc.GoogleEnabled() || len(st.Domains) != 0 {
		t.Fatalf("after Remove: %+v, %v", st, err)
	}
	if _, found := e.stored(t); found {
		t.Error("still stored after Remove")
	}
	if m2 := e.manager(); m2.Load() != nil || m2.Status().Configured() {
		t.Error("back after a restart")
	}
}
