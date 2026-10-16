package tsapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
