package tsapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type seen struct {
	method, path, auth, accept string
	body                       map[string]any
}

func fakeAPI(t *testing.T, status int, resp string) (*httptest.Server, *[]seen) {
	t.Helper()
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			r.ParseForm()
			if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csecret" {
				http.Error(w, "bad client", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"oauth-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		s := seen{method: r.Method, path: r.URL.EscapedPath(), auth: r.Header.Get("Authorization"), accept: r.Header.Get("Accept")}
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			json.Unmarshal(b, &s.body)
		}
		got = append(got, s)
		w.WriteHeader(status)
		io.WriteString(w, resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestSetAttribute(t *testing.T) {
	srv, got := fakeAPI(t, 200, "")
	c, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_API_KEY": "tskey-api-x"})
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Date(2026, 10, 1, 10, 0, 0, 0, time.FixedZone("PDT", -7*3600))
	if err := c.SetAttribute(context.Background(), "nABC123CNTRL", "custom:jit_windows_rdp", true, exp, "jitd req_1"); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("got %d calls", len(*got))
	}
	s := (*got)[0]
	if s.method != "POST" || s.path != "/api/v2/device/nABC123CNTRL/attributes/custom:jit_windows_rdp" {
		t.Errorf("request = %s %s", s.method, s.path)
	}
	if s.auth != "Bearer tskey-api-x" {
		t.Errorf("auth = %q", s.auth)
	}
	want := map[string]any{"value": true, "expiry": "2026-10-01T17:00:00Z", "comment": "jitd req_1"}
	for k, v := range want {
		if s.body[k] != v {
			t.Errorf("body[%s] = %v, want %v", k, s.body[k], v)
		}
	}
	if len(s.body) != len(want) {
		t.Errorf("body = %v", s.body)
	}
}

func TestSetAttributeNoExpiry(t *testing.T) {
	srv, got := fakeAPI(t, 200, "")
	c := &HTTP{BaseURL: srv.URL, HC: srv.Client()}
	if err := c.SetAttribute(context.Background(), "n1", "custom:x", true, time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := (*got)[0].body["expiry"]; ok {
		t.Errorf("zero expiry should be omitted: %v", (*got)[0].body)
	}
}

func TestGetAndDeleteAttributes(t *testing.T) {
	srv, got := fakeAPI(t, 200, `{"attributes":{"custom:jit_x":true,"node:os":"linux"},"expiries":{"custom:jit_x":"2026-10-01T17:00:00Z"}}`)
	c := &HTTP{BaseURL: srv.URL, HC: srv.Client()}
	a, err := c.GetAttributes(context.Background(), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Attributes["custom:jit_x"] != true || !a.Expiries["custom:jit_x"].Equal(time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)) {
		t.Errorf("attributes = %+v", a)
	}
	if err := c.DeleteAttribute(context.Background(), "n1", "custom:jit_x"); err != nil {
		t.Fatal(err)
	}
	if s := (*got)[1]; s.method != "DELETE" || s.path != "/api/v2/device/n1/attributes/custom:jit_x" {
		t.Errorf("delete = %s %s", s.method, s.path)
	}
}

func TestGetPolicy(t *testing.T) {
	srv, got := fakeAPI(t, 200, `{"groups":{"group:sre":["a@example.com"]},"grants":[]}`)
	c := &HTTP{BaseURL: srv.URL, HC: srv.Client()}
	p, err := c.GetPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Groups["group:sre"][0] != "a@example.com" {
		t.Errorf("groups = %v", p.Groups)
	}
	if s := (*got)[0]; s.path != "/api/v2/tailnet/-/acl" || s.accept != "application/json" {
		t.Errorf("policy request = %s accept=%q", s.path, s.accept)
	}
}

// A posture is written either as a list of assertions or as an object with
// "assertions" and "onFailure". Both must decode, and one object form must not
// cost us the rest of the policy.
func TestGetPolicyPostureForms(t *testing.T) {
	srv, _ := fakeAPI(t, 200, `{
		"groups": {"group:sre": ["a@example.com"]},
		"postures": {
			"posture:jitProd": ["custom:jitProd == true"],
			"posture:devicePostureWarning": {
				"assertions": ["node:tsVersion > '2.0'"],
				"onFailure": {
					"showAlerts": ["badge-in-console", "notify-in-client"],
					"endUserMessage": "Your device does not meet IT's security requirements."
				}
			},
			"posture:empty": {"onFailure": {"showAlerts": ["warn-in-client"]}}
		},
		"grants": [{"src": ["autogroup:member"], "dst": ["svc:prod"], "srcPosture": ["posture:jitProd"]}]
	}`)
	c := &HTTP{BaseURL: srv.URL, HC: srv.Client()}
	p, err := c.GetPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Postures["posture:jitProd"]; len(got) != 1 || got[0] != "custom:jitProd == true" {
		t.Errorf("list form = %v", got)
	}
	if got := p.Postures["posture:devicePostureWarning"]; len(got) != 1 || got[0] != "node:tsVersion > '2.0'" {
		t.Errorf("object form = %v", got)
	}
	if got := p.Postures["posture:empty"]; len(got) != 0 {
		t.Errorf("object form without assertions = %v", got)
	}
	// The rest of the policy still arrived.
	if p.Groups["group:sre"][0] != "a@example.com" || len(p.Grants) != 1 {
		t.Errorf("groups = %v, grants = %v", p.Groups, p.Grants)
	}
}

func TestAPIError(t *testing.T) {
	srv, _ := fakeAPI(t, 404, `{"message":"not found"}`)
	c := &HTTP{BaseURL: srv.URL, HC: srv.Client()}
	err := c.DeleteAttribute(context.Background(), "n1", "custom:x")
	if !IsNotFound(err) {
		t.Fatalf("err = %v, want 404 APIError", err)
	}
}

func TestOAuth(t *testing.T) {
	srv, got := fakeAPI(t, 200, `{}`)
	c, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_OAUTH_CLIENT_ID": "cid", "TS_OAUTH_CLIENT_SECRET": "csecret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAttributes(context.Background(), "n1"); err != nil {
		t.Fatal(err)
	}
	if a := (*got)[0].auth; a != "Bearer oauth-token" {
		t.Errorf("auth = %q", a)
	}
}

func TestNoCredentials(t *testing.T) {
	if _, err := NewFromValues(context.Background(), "", map[string]string{"TS_OAUTH_CLIENT_ID": "only-half"}); err == nil {
		t.Fatal("expected error without credentials")
	}
}

// fakeFederated serves /api/v2/oauth/token-exchange: it accepts client_id
// "fid" with any jwt in jwts, returning an access token named after the jwt,
// and records each jwt exchanged. Other paths are API calls that record the
// Authorization header.
func fakeFederated(t *testing.T, expiresIn string) (*httptest.Server, *[]string, *[]string) {
	t.Helper()
	var exchanged, auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token-exchange" {
			r.ParseForm()
			if r.Method != http.MethodPost || r.Form.Get("client_id") != "fid" || r.Form.Get("jwt") == "" {
				http.Error(w, `{"message":"invalid client or token"}`, http.StatusUnauthorized)
				return
			}
			exchanged = append(exchanged, r.Form.Get("jwt"))
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"ts-for-`+r.Form.Get("jwt")+`","token_type":"Bearer"`+expiresIn+`}`)
			return
		}
		auths = append(auths, r.Header.Get("Authorization"))
		io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &exchanged, &auths
}

func TestCredentialKind(t *testing.T) {
	for _, tc := range []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"TS_API_KEY": "k"}, "api_key"},
		{map[string]string{"TS_OAUTH_CLIENT_ID": "id", "TS_OAUTH_CLIENT_SECRET": "s"}, "oauth"},
		{map[string]string{"TS_OAUTH_CLIENT_ID": "id", "TS_ID_TOKEN": "jwt"}, "federated"},
		// A secret wins over an ID token.
		{map[string]string{"TS_OAUTH_CLIENT_ID": "id", "TS_OAUTH_CLIENT_SECRET": "s", "TS_ID_TOKEN": "jwt"}, "oauth"},
		{map[string]string{"TS_ID_TOKEN": "jwt"}, ""},
		{map[string]string{"TS_OAUTH_CLIENT_ID": "id"}, ""},
	} {
		if got := CredentialKind(tc.vars); got != tc.want {
			t.Errorf("CredentialKind(%v) = %q, want %q", tc.vars, got, tc.want)
		}
	}
}

func TestFederatedIdentity(t *testing.T) {
	srv, exchanged, auths := fakeFederated(t, `,"expires_in":3600`)
	c, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_OAUTH_CLIENT_ID": "fid", "TS_ID_TOKEN": "jwt-1"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := c.GetAttributes(context.Background(), "n1"); err != nil {
			t.Fatal(err)
		}
	}
	if len(*exchanged) != 1 || (*exchanged)[0] != "jwt-1" {
		t.Errorf("exchanged = %v, want one exchange of jwt-1 (the token is reused until it expires)", *exchanged)
	}
	for _, a := range *auths {
		if a != "Bearer ts-for-jwt-1" {
			t.Errorf("auth = %q", a)
		}
	}
}

// A token file is read again for each exchange, since platforms rotate the
// tokens in it.
func TestFederatedIdentityTokenFile(t *testing.T) {
	// A 1s token is already inside oauth2's 10s renewal window, so each API
	// call exchanges again.
	srv, exchanged, auths := fakeFederated(t, `,"expires_in":1`)
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte("jwt-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_OAUTH_CLIENT_ID": "fid", "TS_ID_TOKEN": "file:" + path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAttributes(context.Background(), "n1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("jwt-b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAttributes(context.Background(), "n1"); err != nil {
		t.Fatal(err)
	}
	if got := *exchanged; len(got) != 2 || got[0] != "jwt-a" || got[1] != "jwt-b" {
		t.Errorf("exchanged = %v, want [jwt-a jwt-b]", got)
	}
	if got := *auths; len(got) != 2 || got[1] != "Bearer ts-for-jwt-b" {
		t.Errorf("auths = %v", got)
	}
}

func TestFederatedIdentityNoExpiry(t *testing.T) {
	srv, _, _ := fakeFederated(t, "")
	src := &federatedTokenSource{ctx: context.Background(), tokenURL: srv.URL + "/api/v2/oauth/token-exchange", clientID: "fid", idToken: "jwt"}
	tok, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(tok.Expiry); left <= 0 || left > federatedTokenFallbackTTL {
		t.Errorf("expiry in %v, want within %v", left, federatedTokenFallbackTTL)
	}
}

func TestFederatedIdentityErrors(t *testing.T) {
	srv, _, _ := fakeFederated(t, `,"expires_in":3600`)
	if _, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_OAUTH_CLIENT_ID": "fid", "TS_ID_TOKEN": "file:" + t.TempDir() + "/missing"}); err == nil || !strings.Contains(err.Error(), "TS_ID_TOKEN") {
		t.Errorf("missing token file: err = %v", err)
	}
	empty := t.TempDir() + "/empty"
	os.WriteFile(empty, nil, 0o600)
	if _, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_OAUTH_CLIENT_ID": "fid", "TS_ID_TOKEN": "file:" + empty}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty token file: err = %v", err)
	}
	// A rejected exchange surfaces the status and Tailscale's message on the API call.
	c, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_OAUTH_CLIENT_ID": "wrong", "TS_ID_TOKEN": "jwt"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetAttributes(context.Background(), "n1")
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "invalid client or token") {
		t.Errorf("rejected exchange: err = %v", err)
	}
	// It is still the token endpoint's refusal to whoever asks, which is
	// how the setup check knows the credential is at fault, not the network.
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) || re.Response.StatusCode != http.StatusUnauthorized {
		t.Errorf("rejected exchange: no oauth2.RetrieveError in %v", err)
	}
}

func TestCreateAuthKey(t *testing.T) {
	srv, got := fakeAPI(t, 200, `{"id":"kABC","key":"tskey-auth-kABC-secret"}`)
	c, err := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_API_KEY": "tskey-api-x"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreateAuthKey(context.Background(), []string{"tag:jit"}, 10*time.Minute, "jitd node")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "kABC" || k.Key != "tskey-auth-kABC-secret" {
		t.Fatalf("key = %+v", k)
	}
	call := (*got)[0]
	if call.method != "POST" || call.path != "/api/v2/tailnet/-/keys" {
		t.Fatalf("call = %s %s", call.method, call.path)
	}
	create := call.body["capabilities"].(map[string]any)["devices"].(map[string]any)["create"].(map[string]any)
	if create["reusable"] != false || create["ephemeral"] != false || create["preauthorized"] != true {
		t.Errorf("create = %v", create)
	}
	if tags := create["tags"].([]any); len(tags) != 1 || tags[0] != "tag:jit" {
		t.Errorf("tags = %v", tags)
	}
	if call.body["expirySeconds"] != float64(600) || call.body["description"] != "jitd node" {
		t.Errorf("body = %v", call.body)
	}
}

func TestCreateAuthKeyEmptyResponse(t *testing.T) {
	srv, _ := fakeAPI(t, 200, `{}`)
	c, _ := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_API_KEY": "tskey-api-x"})
	if _, err := c.CreateAuthKey(context.Background(), []string{"tag:jit"}, time.Minute, "x"); err == nil {
		t.Fatal("no error for a response without a key")
	}
}

func TestDeleteAuthKey(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{{200, false}, {404, false}, {403, true}} {
		srv, got := fakeAPI(t, tc.status, `{}`)
		c, _ := NewFromValues(context.Background(), srv.URL, map[string]string{"TS_API_KEY": "tskey-api-x"})
		err := c.DeleteAuthKey(context.Background(), "kABC")
		if (err != nil) != tc.wantErr {
			t.Errorf("status %d: err = %v, wantErr %v", tc.status, err, tc.wantErr)
		}
		if call := (*got)[0]; call.method != "DELETE" || call.path != "/api/v2/tailnet/-/keys/kABC" {
			t.Errorf("call = %s %s", call.method, call.path)
		}
	}
}
