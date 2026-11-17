package setup

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// newSaver is a checker with a store and no credentials in the file. The
// API accepts any secret but "tskey-client-bad", and remembers the last
// variables it was built from.
func newSaver(t *testing.T) (c *Checker, target *tsapi.Switchable, used *map[string]string) {
	t.Helper()
	c, target = newChecker(t, &fakeTS{}, "")
	st, err := jit.Open(filepath.Join(t.TempDir(), "jit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c.Store = st
	used = new(map[string]string)
	c.NewClient = func(_ context.Context, _ string, vars map[string]string) (tsapi.Client, error) {
		*used = vars
		if vars["TS_OAUTH_CLIENT_SECRET"] == "tskey-client-bad" {
			return &fakeTS{policyErr: &tsapi.APIError{Method: "GET", Path: "/policy", Status: http.StatusUnauthorized, Body: "no"}}, nil
		}
		if vars["TS_OAUTH_CLIENT_SECRET"] == "tskey-client-readonly" {
			return &fakeTS{writeErr: &tsapi.APIError{Method: "POST", Path: "/attr", Status: http.StatusForbidden, Body: "no"}}, nil
		}
		return &fakeTS{}, nil
	}
	return c, target, used
}

func code(err error) string {
	if e, ok := err.(*jit.Error); ok {
		return e.Code
	}
	return ""
}

func TestSaveTestsFirst(t *testing.T) {
	ctx := context.Background()
	c, target, _ := newSaver(t)
	if res := c.Run(ctx); res.OK || !res.Credentials.CanSave || !strings.Contains(byName(res, "Credentials").Fix, "Connect Tailscale on this page") {
		t.Fatalf("before setup: %+v", res)
	}

	// A refused credential stores nothing, says which check failed and why,
	// and never repeats the secret.
	for _, in := range []Input{
		{ClientID: "kABC", ClientSecret: "tskey-client-bad"},
		{ClientID: "kABC", ClientSecret: "tskey-client-readonly"},
	} {
		_, err := c.Save(ctx, "root", in)
		if code(err) != "bad_request" || strings.Contains(err.Error(), in.ClientSecret) || !strings.Contains(err.Error(), "Nothing was saved") {
			t.Errorf("%s: %v", in.ClientSecret, err)
		}
		if found, _ := c.Store.GetSetting(settingKey, new(saved)); found {
			t.Errorf("%s was stored", in.ClientSecret)
		}
		if _, err := target.GetPolicy(ctx); err == nil {
			t.Errorf("%s is being served with", in.ClientSecret)
		}
	}
	if _, err := c.Save(ctx, "root", Input{ClientID: "kABC", ClientSecret: "tskey-client-readonly"}); !strings.Contains(err.Error(), "devices:posture_attributes (write)") {
		t.Errorf("a missing scope is not named: %v", err)
	}
	for _, in := range []Input{{}, {ClientID: "kABC"}, {ClientSecret: "tskey-client-x"}, {ClientID: "k", ClientSecret: "s", APIKey: "tskey-api-x"}, {ClientID: "tskey-client-kABC-secret", ClientSecret: "kABC"}} {
		if _, err := c.Save(ctx, "root", in); code(err) != "bad_request" {
			t.Errorf("%+v: %v", in, err)
		}
	}

	// A working one is stored and served with straight away.
	res, err := c.Save(ctx, "root", Input{ClientID: " kABC ", ClientSecret: " tskey-client-kABC-SECRETSECRET\n"})
	if err != nil || !res.OK {
		t.Fatalf("save: %v %+v", err, res)
	}
	cr := res.Credentials
	if cr.Source != "ui" || cr.Kind != "oauth" || cr.ClientID != "kABC" || cr.SavedBy != "root" || cr.SavedAt.IsZero() {
		t.Errorf("credentials: %+v", cr)
	}
	if _, err := target.GetPolicy(ctx); err != nil {
		t.Errorf("not serving with the saved credential: %v", err)
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), "SECRETSECRET") {
		t.Error("the result carries the secret")
	}
	if !strings.Contains(byName(res, "Credentials").Detail, "saved on this page") {
		t.Errorf("credentials check: %+v", byName(res, "Credentials"))
	}

	// A refused replacement keeps the one in use.
	if _, err := c.Save(ctx, "root", Input{ClientID: "kNEW", ClientSecret: "tskey-client-bad"}); err == nil {
		t.Fatal("bad replacement saved")
	}
	if res := c.Run(ctx); !res.OK || res.Credentials.ClientID != "kABC" {
		t.Errorf("after a refused replacement: %+v", res.Credentials)
	}

	// An API access token works too, and shows only its last four.
	res, err = c.Save(ctx, "root", Input{APIKey: "tskey-api-kXYZ-TOKENTOKEN1234"})
	if err != nil || res.Credentials.Kind != "api_key" || res.Credentials.KeyHint != "…1234" || res.Credentials.ClientID != "" {
		t.Fatalf("api key: %v %+v", err, res)
	}

	// Remove: nothing to serve with.
	res, err = c.Remove(ctx, "root")
	if err != nil || res.OK || res.Credentials.Source != "" {
		t.Fatalf("remove: %v %+v", err, res)
	}
	if _, err := target.GetPolicy(ctx); err == nil {
		t.Error("still serving after remove")
	}
}

func TestSavedSurvivesRestartAndFileWins(t *testing.T) {
	ctx := context.Background()
	c, _, used := newSaver(t)
	if _, err := c.Save(ctx, "root", Input{ClientID: "kABC", ClientSecret: "tskey-client-saved"}); err != nil {
		t.Fatal(err)
	}

	// A new checker on the same store, as after a restart.
	again := &Checker{EnvFile: c.EnvFile, Store: c.Store, Tag: c.Tag, Node: c.Node, NewClient: c.NewClient, Target: &tsapi.Switchable{}}
	if res := again.Run(ctx); !res.OK || res.Credentials.Source != "ui" || (*used)["TS_OAUTH_CLIENT_SECRET"] != "tskey-client-saved" {
		t.Fatalf("after a restart: %+v", res.Credentials)
	}

	// The file wins once it holds a credential, and the page cannot change it.
	os.WriteFile(c.EnvFile, []byte("TS_OAUTH_CLIENT_ID=kFILE\nTS_OAUTH_CLIENT_SECRET=tskey-client-file\n"), 0o600)
	res := again.Run(ctx)
	if !res.OK || res.Credentials.Source != "env" || !res.Credentials.Shadowed || res.Credentials.ClientID != "" || (*used)["TS_OAUTH_CLIENT_SECRET"] != "tskey-client-file" {
		t.Fatalf("file should win: %+v", res.Credentials)
	}
	if _, err := again.Save(ctx, "root", Input{ClientID: "kNEW", ClientSecret: "tskey-client-new"}); code(err) != "conflict" {
		t.Errorf("save while the file wins: %v", err)
	}
	// The shadowed one can be cleared; the file's stays in use.
	if res, err := again.Remove(ctx, "root"); err != nil || !res.OK || res.Credentials.Shadowed {
		t.Errorf("remove the shadowed one: %v %+v", err, res.Credentials)
	}

	// Without a store there is nothing to save to.
	plain, _ := newChecker(t, &fakeTS{}, "")
	if _, err := plain.Save(ctx, "root", Input{APIKey: "tskey-api-x"}); code(err) != "not_found" {
		t.Errorf("save without a store: %v", err)
	}
}
