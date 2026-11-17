package okta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Explain turns each way Okta refuses a credential into what is wrong and
// what to change, for the Okta page.
func TestExplain(t *testing.T) {
	ctx := context.Background()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, err error, app bool, what, fix string) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: the check passed", name)
			return
		}
		gotWhat, gotFix := Explain(err, app)
		if !strings.Contains(gotWhat, what) || !strings.Contains(gotFix, fix) {
			t.Errorf("%s: Explain(%v) = %q, %q; want %q and %q in them", name, err, gotWhat, gotFix, what, fix)
		}
	}

	// A key Okta does not know, then an app that still wants DPoP.
	s, c := newAppOrg(t, k, rsaPEM(t, other, true), nil)
	check("wrong key", c.Check(ctx), true, "did not accept the client ID and private key", "key ID")
	s.dpop = true
	check("dpop", c.Check(ctx), true, "DPoP", "Proof of Possession")

	// A token Okta does not know.
	tok, err := NewFromValues(map[string]string{"OKTA_ORG_URL": s.base, "OKTA_API_TOKEN": "nope"})
	if err != nil {
		t.Fatal(err)
	}
	check("bad token", tok.Check(ctx), false, "did not accept the API token", "new token")

	// Signed in, but no admin role; and scopes Okta will not give.
	check("no role", &APIError{Status: http.StatusForbidden, Summary: "You do not have permission to perform the requested action"}, true,
		"does not let it look at groups (You do not have permission", "Group Administrator")
	check("no role, token", &APIError{Status: http.StatusForbidden}, false, "accepted the token", "Group Administrator")
	check("scope", &TokenError{Status: 400, Code: "invalid_scope", Description: "One or more scopes are not configured for the authorization server resource."}, true,
		"scopes jitd asks for", "okta.groups.manage")

	// An address that is not an Okta org.
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html>not here</html>")
	}))
	defer web.Close()
	notOkta, err := NewFromValues(map[string]string{"OKTA_ORG_URL": web.URL, "OKTA_CLIENT_ID": "0oaJIT", "OKTA_PRIVATE_KEY": rsaPEM(t, k, true)})
	if err != nil {
		t.Fatal(err)
	}
	check("not okta", notOkta.Check(ctx), true, "did not answer like an Okta org", "-admin")
	web.Close()
	check("unreachable", notOkta.Check(ctx), true, "could not reach Okta", "Okta address")

	if what, fix := Explain(nil, true); what != "" || fix != "" {
		t.Errorf("Explain(nil) = %q, %q", what, fix)
	}
	// No answer ever carries the key.
	for _, e := range []error{c.Check(ctx), notOkta.Check(ctx)} {
		if what, fix := Explain(e, true); strings.Contains(what+fix, "PRIVATE KEY") {
			t.Errorf("the explanation quotes the key: %q %q", what, fix)
		}
	}
}

func TestKeyFingerprint(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	a, b := KeyFingerprint(rsaPEM(t, k, true)), KeyFingerprint(rsaPEM(t, k, false))
	if len(a) != 16 || a != b {
		t.Errorf("one key in two encodings: %q and %q", a, b)
	}
	if o := KeyFingerprint(rsaPEM(t, other, true)); o == a || o == "" {
		t.Errorf("another key has fingerprint %q, the first %q", o, a)
	}
	if got := KeyFingerprint("not a key"); got != "" {
		t.Errorf("fingerprint of garbage = %q", got)
	}
	if strings.Contains(rsaPEM(t, k, true), a) {
		t.Error("the fingerprint is a piece of the key")
	}
}

// Settings saved on the Okta page become the same variables an env file has.
func TestSettingsVars(t *testing.T) {
	app := Settings{OrgURL: "https://x.okta.com", ClientID: "0oa1", PrivateKey: "pem", PrivateKeyID: "kid1", Scopes: "okta.users.read"}.Vars()
	if !Configured(app) || app["OKTA_ORG_URL"] != "https://x.okta.com" || app["OKTA_CLIENT_ID"] != "0oa1" || app["OKTA_PRIVATE_KEY"] != "pem" ||
		app["OKTA_PRIVATE_KEY_ID"] != "kid1" || app["OKTA_SCOPES"] != "okta.users.read" || app["OKTA_API_TOKEN"] != "" {
		t.Errorf("service app vars = %v", app)
	}
	tok := Settings{OrgURL: "https://x.okta.com", APIToken: "t"}.Vars()
	if !Configured(tok) || tok["OKTA_API_TOKEN"] != "t" || tok["OKTA_CLIENT_ID"] != "" {
		t.Errorf("token vars = %v", tok)
	}
	if Configured(Settings{}.Vars()) {
		t.Error("empty settings count as set up")
	}
}

// Dynamic builds its client with New when one is given, and again when the
// credentials change.
func TestDynamicNew(t *testing.T) {
	vars := map[string]string{}
	built := 0
	f := NewFake()
	d := &Dynamic{
		Load: func() (map[string]string, error) { return vars, nil },
		New: func(map[string]string) (Client, error) {
			built++
			return f, nil
		},
	}
	if d.Enabled() || built != 0 {
		t.Fatalf("enabled = %v, built = %d with nothing set", d.Enabled(), built)
	}
	vars = map[string]string{"OKTA_ORG_URL": "https://x.okta.com", "OKTA_API_TOKEN": "one"}
	for range 2 {
		if err := d.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !d.Enabled() || built != 1 {
		t.Fatalf("enabled = %v, built = %d after setting credentials", d.Enabled(), built)
	}
	vars = map[string]string{"OKTA_ORG_URL": "https://x.okta.com", "OKTA_API_TOKEN": "two"}
	if err := d.Check(context.Background()); err != nil || built != 2 {
		t.Fatalf("after a new token: err = %v, built = %d", err, built)
	}
	vars = map[string]string{}
	if err := d.Check(context.Background()); err == nil || d.Enabled() {
		t.Errorf("after removing the credentials: err = %v, enabled = %v", err, d.Enabled())
	}
}
