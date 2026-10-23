package jithttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

type fakeTS struct{ calls []string }

func (f *fakeTS) SetAttribute(ctx context.Context, device, key string, value any, expiry time.Time, comment string) error {
	f.calls = append(f.calls, "SET "+device+" "+key)
	return nil
}
func (f *fakeTS) GetAttributes(ctx context.Context, device string) (tsapi.Attributes, error) {
	return tsapi.Attributes{Attributes: map[string]any{"custom:jit_windows_rdp": true}}, nil
}
func (f *fakeTS) DeleteAttribute(ctx context.Context, device, key string) error {
	f.calls = append(f.calls, "DEL "+device+" "+key)
	return nil
}
func (f *fakeTS) GetPolicy(ctx context.Context) (tsapi.Policy, error) { return tsapi.Policy{}, nil }

// The test resolver takes the caller from the X-Test-User header so one server
// can be driven as several people. jitd itself only uses WhoIs.
var people = map[string]jit.Identity{
	"alice": {Login: "alice@example.com", DeviceID: "nALICE", DeviceName: "alice-laptop"},
	"bob":   {Login: "bob@example.com", DeviceID: "nBOB", DeviceName: "bob-mac"},
	"root":  {Login: "root@example.com", DeviceID: "nROOT", DeviceName: "root-mac"}, // the admin
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeTS) {
	t.Helper()
	srv, ts, _ := newTestServerWith(t, nil)
	return srv, ts
}

// newTestServerWith lets a test adjust the Server before it is served.
func newTestServerWith(t *testing.T, adjust func(*Server)) (*httptest.Server, *fakeTS, *Server) {
	t.Helper()
	st, err := jit.Open(filepath.Join(t.TempDir(), "jit.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := &fakeTS{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &jit.Service{Store: st, TS: ts, Log: log, Admins: []jit.Principal{"root@example.com"}}
	h := &Server{
		Svc: svc, TS: ts, JITTag: "tag:jit", Log: log, BaseURL: "http://jit.example.ts.net/",
		Resolver: jit.ResolverFunc(func(ctx context.Context, r *http.Request) (jit.Identity, error) {
			id, ok := people[r.Header.Get("X-Test-User")]
			if !ok {
				return jit.Identity{}, &jit.Error{Code: "identity_unavailable", Status: 401, Message: "unknown caller"}
			}
			return id, nil
		}),
	}
	if adjust != nil {
		adjust(h)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)
	return srv, ts, h
}

// getPage fetches a web page as user.
func getPage(t *testing.T, srv *httptest.Server, user, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	req.Header.Set("X-Test-User", user)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func call(t *testing.T, srv *httptest.Server, user, method, path string, body any, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: decoding %q: %v", method, path, b, err)
		}
	}
	return resp.StatusCode
}

type apiErr struct {
	Error struct{ Code, Message string } `json:"error"`
}

func TestAPIFlow(t *testing.T) {
	srv, ts := newTestServer(t)

	var me jit.Identity
	if code := call(t, srv, "alice", "GET", "/v1/me", nil, &me); code != 200 || me.Login != "alice@example.com" {
		t.Fatalf("me: %d %+v", code, me)
	}
	var e apiErr
	if code := call(t, srv, "", "GET", "/v1/me", nil, &e); code != 401 || e.Error.Code != "identity_unavailable" {
		t.Fatalf("anonymous me: %d %+v", code, e)
	}

	var wf jit.Workflow
	if code := call(t, srv, "alice", "POST", "/v1/workflows", map[string]any{"name": "x"}, &e); code != 403 {
		t.Fatalf("non-admin create workflow: %d %+v", code, e)
	}
	code := call(t, srv, "root", "POST", "/v1/workflows", map[string]any{
		"name": "RDP", "attribute": "windows_rdp", "resources": []map[string]string{{"name": "svc:windows-rdp", "description": "Windows jump host"}},
		"requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"},
		"max_duration": "1h",
	}, &wf)
	if code != 201 || wf.ID == "" {
		t.Fatalf("create workflow: %d %+v", code, wf)
	}
	if code := call(t, srv, "root", "POST", "/v1/workflows", map[string]any{"name": "bad"}, &e); code != 400 || e.Error.Code != "bad_request" {
		t.Fatalf("invalid workflow: %d %+v", code, e)
	}
	if code := call(t, srv, "root", "POST", "/v1/workflows", map[string]any{"nme": "typo"}, &e); code != 400 {
		t.Fatalf("unknown field: %d %+v", code, e)
	}

	var reqable struct {
		Requestable []jit.Requestable `json:"requestable"`
	}
	if code := call(t, srv, "alice", "GET", "/v1/requestable", nil, &reqable); code != 200 || len(reqable.Requestable) != 1 || reqable.Requestable[0].Attribute != "custom:jit_windows_rdp" || reqable.Requestable[0].Resources[0].Name != "svc:windows-rdp" || reqable.Requestable[0].Policy == nil {
		t.Fatalf("requestable: %d %+v", code, reqable)
	}

	var r jit.AccessRequest
	code = call(t, srv, "alice", "POST", "/v1/requests", map[string]any{"workflow_id": wf.ID, "duration": "15m", "reason": "demo"}, &r)
	if code != 201 || r.Status != jit.StatusPending || r.TargetDeviceID != "nALICE" {
		t.Fatalf("submit: %d %+v", code, r)
	}
	if r.URL != "http://jit.example.ts.net/requests/"+r.ID {
		t.Errorf("submit url = %q", r.URL)
	}
	// A duplicate points at the live request, with its URL.
	var dup struct {
		Error struct {
			Code, Message, URL string
			RequestID          string `json:"request_id"`
		} `json:"error"`
	}
	if code := call(t, srv, "alice", "POST", "/v1/requests", map[string]any{"workflow_id": wf.ID, "duration": "15m", "reason": "again"}, &dup); code != 409 || dup.Error.RequestID != r.ID || dup.Error.URL != r.URL {
		t.Fatalf("duplicate submit: %d %+v", code, dup)
	}

	// Self-approval is off and alice is not an approver.
	if code := call(t, srv, "alice", "POST", "/v1/requests/"+r.ID+"/approve", nil, &e); code != 403 {
		t.Fatalf("alice approve: %d %+v", code, e)
	}
	if code := call(t, srv, "bob", "POST", "/v1/requests/"+r.ID+"/approve", map[string]string{"note": "go"}, &r); code != 200 || r.Status != jit.StatusApproved {
		t.Fatalf("bob approve: %d %+v", code, r)
	}
	if fmt.Sprint(ts.calls) != "[SET nALICE custom:jit_windows_rdp]" {
		t.Errorf("API calls = %v", ts.calls)
	}

	var got jit.AccessRequest
	if code := call(t, srv, "alice", "GET", "/v1/requests/"+r.ID, nil, &got); code != 200 || got.Status != jit.StatusApproved || len(got.Timeline) != 2 || got.URL == "" {
		t.Fatalf("get: %d %+v", code, got)
	}
	if code := call(t, srv, "", "GET", "/v1/requests/"+r.ID, nil, &e); code != 401 {
		t.Fatalf("anonymous get: %d", code)
	}
	var list struct{ Requests []jit.AccessRequest }
	if code := call(t, srv, "bob", "GET", "/v1/requests?scope=mine", nil, &list); code != 200 || len(list.Requests) != 0 {
		t.Fatalf("bob's requests: %d %+v", code, list)
	}
	if code := call(t, srv, "bob", "GET", "/v1/requests?scope=approvals", nil, &list); code != 200 || len(list.Requests) != 1 {
		t.Fatalf("bob's approvals: %d %+v", code, list)
	}
	if code := call(t, srv, "root", "GET", "/v1/requests?status=approved", nil, &list); code != 200 || len(list.Requests) != 1 {
		t.Fatalf("approved list: %d %+v", code, list)
	}

	if code := call(t, srv, "alice", "POST", "/v1/requests/"+r.ID+"/revoke", nil, &r); code != 200 || r.Status != jit.StatusRevoked {
		t.Fatalf("revoke: %d %+v", code, r)
	}
	if code := call(t, srv, "alice", "POST", "/v1/requests/"+r.ID+"/bogus", nil, &e); code != 404 {
		t.Fatalf("bogus action: %d", code)
	}
	if code := call(t, srv, "root", "DELETE", "/v1/workflows/"+wf.ID, nil, nil); code != 204 {
		t.Fatalf("delete workflow: %d", code)
	}
}

func TestCancelAndSameSite(t *testing.T) {
	srv, _ := newTestServer(t)
	var wf jit.Workflow
	call(t, srv, "root", "POST", "/v1/workflows", map[string]any{
		"name": "RDP", "attribute": "windows_rdp", "resources": []map[string]string{{"name": "svc:windows-rdp", "description": "Windows jump host"}},
		"requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"},
	}, &wf)
	var r jit.AccessRequest
	call(t, srv, "alice", "POST", "/v1/requests", map[string]any{"workflow_id": wf.ID, "duration": "15m", "reason": "demo"}, &r)

	// A cross-site browser POST (as a malicious page would send) is refused.
	req, _ := http.NewRequest("POST", srv.URL+"/v1/requests/"+r.ID+"/cancel", strings.NewReader("{}"))
	req.Header.Set("X-Test-User", "alice")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-site cancel: %d", resp.StatusCode)
	}

	var e apiErr
	if code := call(t, srv, "bob", "POST", "/v1/requests/"+r.ID+"/cancel", nil, &e); code != 403 {
		t.Fatalf("bob cancel: %d %+v", code, e)
	}
	if code := call(t, srv, "alice", "POST", "/v1/requests/"+r.ID+"/cancel", nil, &r); code != 200 || r.Status != jit.StatusCancelled {
		t.Fatalf("alice cancel: %d %+v", code, r)
	}
}

func TestPolicySnippetEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	call(t, srv, "root", "POST", "/v1/workflows", map[string]any{
		"name": "RDP", "attribute": "windows_rdp", "resources": []map[string]string{{"name": "svc:windows-rdp", "description": "Windows jump host"}},
		"requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"},
	}, nil)
	req, _ := http.NewRequest("GET", srv.URL+"/v1/policy-snippet", nil)
	req.Header.Set("X-Test-User", "root")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"posture:jit_windows_rdp", `"srcPosture"`, `"svc:windows-rdp"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("snippet missing %s:\n%s", want, b)
		}
	}
}

func TestWebPages(t *testing.T) {
	srv, _ := newTestServer(t)
	var wf jit.Workflow
	call(t, srv, "root", "POST", "/v1/workflows", map[string]any{
		"name": "RDP flow", "attribute": "windows_rdp", "resources": []map[string]string{{"name": "svc:windows-rdp", "description": "Windows jump host"}},
		"requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"},
	}, &wf)
	var r jit.AccessRequest
	call(t, srv, "alice", "POST", "/v1/requests", map[string]any{"workflow_id": wf.ID, "reason": "demo reason"}, &r)

	get := func(user, path string) (int, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("X-Test-User", user)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, tc := range []struct {
		user, path string
		status     int
		want       []string
	}{
		{"root", "/workflows", 200, []string{"RDP flow", "windows-rdp", "bob@example.com"}},
		{"root", "/workflows/new", 200, []string{"New approval flow", `data-form="workflow"`}},
		{"root", "/workflows/" + wf.ID, 200, []string{`value="RDP flow"`, "Delete"}},
		{"alice", "/workflows", 403, []string{"Admins only"}},
		{"root", "/admin", 200, []string{"Admin overview", "All requests", "demo reason"}},
		{"root", "/admin/requests", 200, []string{"All requests", "demo reason"}},
		{"alice", "/admin", 403, []string{"Admins only"}},
		{"alice", "/", 200, []string{"Overview", "Request access"}},
		{"alice", "/policy", 403, []string{"Admins only"}},
		{"bob", "/requests?scope=approvals", 200, []string{"demo reason"}},
		{"bob", "/requests/" + r.ID, 200, []string{"demo reason"}},
		{"alice", "/requests", 200, []string{"alice@example.com", "pending"}},
		{"alice", "/requests/new", 200, []string{"RDP flow", `svc:windows-rdp`, "Windows jump host", `name="dur_n"`, `name="dur_unit"`, `data-default="3600"`}},
		{"root", "/admin/workflows", 200, []string{"custom:jit_windows_rdp", "⚠ no policy source configured"}},
		{"root", "/admin/workflows/" + wf.ID, 200, []string{`value="windows_rdp"`, "Gives access to", "Policy check", `value="svc:windows-rdp"`, `value="Windows jump host"`}},
		{"alice", "/", 200, []string{"Overview", "Waiting for approval", "RDP flow", "demo reason"}},
		{"bob", "/", 200, []string{"/v1/requests/" + r.ID + "/approve"}},
		{"alice", "/requests/" + r.ID, 200, []string{"demo reason", "Cancel request"}},
		{"root", "/requests/" + r.ID, 200, []string{"demo reason", "custom:jit_windows_rdp"}},
		{"root", "/api/docs", 200, []string{"swagger-ui"}},
		{"alice", "/api/docs", 403, []string{"Admins only"}},
		{"bob", "/requests/" + r.ID, 200, []string{"/approve", "/decline"}},
		{"root", "/policy", 200, []string{"posture:jit_windows_rdp"}},
		{"nobody", "/requests", 200, []string{"No identity"}},
		{"alice", "/requests/req_missing", 404, []string{"not found"}},
		{"alice", "/static/app.js", 200, []string{"/v1/requests"}},
		{"root", "/admin/setup", 200, []string{"no setup check", "Setup"}},
		{"alice", "/admin/setup", 403, []string{"Admins only"}},
	} {
		status, body := get(tc.user, tc.path)
		if status != tc.status {
			t.Errorf("%s as %s: status %d, want %d", tc.path, tc.user, status, tc.status)
		}
		for _, w := range tc.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s as %s: missing %q", tc.path, tc.user, w)
			}
		}
	}
	// Alice (requester, not approver) must not get approve buttons.
	for _, path := range []string{"/requests/" + r.ID, "/"} {
		if _, body := get("alice", path); strings.Contains(body, "/approve") {
			t.Errorf("alice sees an approve button on %s", path)
		}
	}
}

// TestSetupPage runs the setup check against a missing credentials file and
// checks the page says what to fix, then fixes it and checks again.
func TestListRequestsRejectsUnknownFilters(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, q := range []string{"?mine=1&scope=bogus", "?status=bogus"} {
		if code := call(t, srv, "alice", "GET", "/v1/requests"+q, nil, nil); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", q, code)
		}
	}
	if code := call(t, srv, "alice", "GET", "/v1/requests?scope=mine&status=pending", nil, nil); code != 200 {
		t.Errorf("valid filters: %d", code)
	}
}

func TestSetupPage(t *testing.T) {
	for _, k := range tsapi.CredentialVars {
		t.Setenv(k, "")
	}
	envFile := filepath.Join(t.TempDir(), "env")
	srv, _, _ := newTestServerWith(t, func(s *Server) {
		s.Setup = &setup.Checker{
			EnvFile: envFile, Tag: "tag:jit", Target: &tsapi.Switchable{}, Log: s.Log,
			Node: func(context.Context) (setup.Node, error) {
				return setup.Node{ID: "nJIT", Tags: []string{"tag:jit"}}, nil
			},
			NewClient: func(context.Context, string, map[string]string) (tsapi.Client, error) { return s.TS, nil },
		}
	})
	var res setup.Result
	if st := call(t, srv, "alice", "GET", "/v1/setup", nil, nil); st != 403 {
		t.Fatalf("non-admin: %d", st)
	}
	call(t, srv, "root", "GET", "/v1/setup", nil, &res)
	if res.OK || !strings.Contains(res.Checks[1].Detail, "does not exist") {
		t.Fatalf("expected a failed check on the missing file, got %+v", res.Checks)
	}
	status, body := getPage(t, srv, "root", "/admin/setup")
	if status != 200 || !strings.Contains(body, "Something needs fixing") || !strings.Contains(body, envFile) {
		t.Fatalf("page: %d %q", status, body)
	}
	if _, body := getPage(t, srv, "root", "/"); !strings.Contains(body, `class="dot bad"`) {
		t.Error("sidebar should flag the failed check")
	}
	os.WriteFile(envFile, []byte("TS_OAUTH_CLIENT_ID=id\nTS_OAUTH_CLIENT_SECRET=hunter2value\n"), 0o600)
	call(t, srv, "root", "POST", "/v1/setup/check", nil, &res)
	if !res.OK {
		t.Fatalf("after fixing the file: %+v", res.Checks)
	}
	status, body = getPage(t, srv, "root", "/admin/setup")
	if status != 200 || !strings.Contains(body, "Everything works") || strings.Contains(body, "hunter2value") {
		t.Fatalf("page after fix: %d, shows secret=%v", status, strings.Contains(body, "hunter2value"))
	}
}

// A page whose DNS name was rebound to jitd's address sends its own name as
// Host; jitd must refuse it, even when the request looks same-origin.
func TestUnknownHostRefused(t *testing.T) {
	srv, _, _ := newTestServerWith(t, func(s *Server) { s.Hosts = []string{"jit", "jit.example.ts.net", "127.0.0.1"} })
	for _, tc := range []struct {
		host string
		want int
	}{
		{"evil.example", http.StatusMisdirectedRequest},
		{"jit", http.StatusNotFound}, // reached the handler
		{"JIT.example.ts.net.", http.StatusNotFound},
		{"jit:80", http.StatusNotFound},
	} {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/requests/req_missing/cancel", strings.NewReader(`{}`))
		req.Host = tc.host
		req.Header.Set("X-Test-User", "root")
		req.Header.Set("Origin", "http://"+tc.host)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("Host %q: status %d, want %d", tc.host, resp.StatusCode, tc.want)
		}
	}
}

func TestPluginURL(t *testing.T) {
	for base, want := range map[string]string{
		"http://jit.example.ts.net/":    "",
		"http://jit":                    "",
		"http://jit-1.example.ts.net":   "http://jit-1",
		"http://access.example.ts.net/": "http://access",
		"https://jit.example.ts.net":    "https://jit.example.ts.net",
		"http://100.64.0.1":             "http://100.64.0.1",
	} {
		if got := (&Server{BaseURL: base}).pluginURL(); got != want {
			t.Errorf("pluginURL(%q) = %q, want %q", base, got, want)
		}
	}
}

func TestHelpTellsPluginURL(t *testing.T) {
	srv, _ := newTestServer(t)
	if _, body := getPage(t, srv, "alice", "/help"); strings.Contains(body, "/plugin configure") {
		t.Error("help mentions configuring the plugin although jitd is at http://jit")
	}
	srv, _, _ = newTestServerWith(t, func(s *Server) { s.BaseURL = "http://jit-1.example.ts.net" })
	if _, body := getPage(t, srv, "alice", "/help"); !strings.Contains(body, "<code>http://jit-1</code>") {
		t.Error("help does not tell people to set the plugin's jitd URL to http://jit-1")
	}
}
