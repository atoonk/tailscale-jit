package jitmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeTS says yes to every write. With present it reports the attribute as
// set, so an approval is confirmed on the first read-back; reads counts the
// read-backs. policy is what GetPolicy returns.
type fakeTS struct {
	present bool
	policy  tsapi.Policy
	reads   atomic.Int64
}

func (*fakeTS) SetAttribute(context.Context, string, string, any, time.Time, string) error {
	return nil
}
func (f *fakeTS) GetAttributes(context.Context, string) (tsapi.Attributes, error) {
	f.reads.Add(1)
	if !f.present {
		return tsapi.Attributes{}, nil
	}
	return tsapi.Attributes{Attributes: map[string]any{"custom:jit_db_ro": true}}, nil
}
func (*fakeTS) DeleteAttribute(context.Context, string, string) error { return nil }
func (f *fakeTS) GetPolicy(context.Context) (tsapi.Policy, error)     { return f.policy, nil }

// gatedPolicy is a tailnet policy in which the test flow's posture gates a
// grant, so approving it unlocks something.
func gatedPolicy() tsapi.Policy {
	return tsapi.Policy{
		Postures: map[string]tsapi.Posture{"posture:jit_db_ro": {"custom:jit_db_ro == true"}},
		Grants:   []tsapi.Grant{{Src: []string{"autogroup:member"}, Dst: []string{"svc:mysql-prod"}, SrcPosture: []string{"posture:jit_db_ro"}}},
	}
}

var people = map[string]jit.Identity{
	"maya": {Login: "maya@example.com", DeviceID: "nMAYA", DeviceName: "maya-laptop"},
	"sam":  {Login: "sam@example.com", DeviceID: "nSAM", DeviceName: "sam-mac"},
}

type env struct {
	svc  *jit.Service
	ts   *fakeTS
	url  string
	flow *jit.Workflow
}

func newEnv(t *testing.T) *env {
	return newEnvWith(t, &fakeTS{present: true, policy: gatedPolicy()})
}

func newEnvWith(t *testing.T, ts *fakeTS) *env {
	t.Helper()
	st, err := jit.Open(filepath.Join(t.TempDir(), "jit.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &jit.Service{Store: st, TS: ts, Log: log}
	svc.PolicyCache = &jit.PolicyCache{TS: ts, TTL: time.Minute, Log: log}
	flow, err := svc.CreateWorkflow(jit.Workflow{Name: "Database access (read-only)", Description: "Prod MySQL, read replica", Attribute: "db_ro",
		Resources:  []jit.Resource{{Name: "svc:mysql-prod", Description: "Production MySQL"}},
		Requesters: []jit.Principal{"maya@example.com"}, Approvers: []jit.Principal{"sam@example.com"},
		MaxDuration: jit.Duration(4 * time.Hour), DefaultDuration: jit.Duration(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Svc: svc, BaseURL: "http://jit", Log: log, Resolver: jit.ResolverFunc(func(ctx context.Context, r *http.Request) (jit.Identity, error) {
		id, ok := people[r.Header.Get("X-Test-User")]
		if !ok {
			return jit.Identity{}, &jit.Error{Code: "identity_unavailable", Status: 401, Message: "unknown caller"}
		}
		return id, nil
	})}
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{svc: svc, ts: ts, url: srv.URL + "/mcp", flow: flow}
}

// asUser is an HTTP client that identifies as user.
type asUser struct{ user string }

func (u asUser) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-User", u.user)
	return http.DefaultTransport.RoundTrip(r)
}

func (e *env) connect(t *testing.T, user string) *mcp.ClientSession {
	t.Helper()
	tr := &mcp.StreamableClientTransport{Endpoint: e.url, HTTPClient: &http.Client{Transport: asUser{user}}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s: %s", name, textOf(res))
	}
	var sc map[string]any
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &sc)
	return res, sc
}

func textOf(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

func TestToolsAndApp(t *testing.T) {
	e := newEnv(t)
	cs := e.connect(t, "maya")

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		ui, _ := tl.Meta["ui"].(map[string]any)
		if ui["resourceUri"] != appURI {
			t.Errorf("%s: _meta.ui = %v, want resourceUri %s", tl.Name, tl.Meta["ui"], appURI)
		}
	}
	if got := strings.Join(names, " "); got != "cancel_access_request get_access_request list_requestable request_access wait_for_access" {
		t.Errorf("tools = %s", got)
	}

	rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: appURI})
	if err != nil {
		t.Fatal(err)
	}
	if c := rr.Contents[0]; c.MIMEType != appMIME || !strings.Contains(c.Text, "ui/initialize") || !strings.HasPrefix(c.Text, "<!DOCTYPE html>") {
		t.Errorf("app resource = %s %.40q", c.MIMEType, c.Text)
	}

	res, sc := call(t, cs, "list_requestable", nil)
	if txt := textOf(res); !strings.Contains(txt, "maya@example.com on maya-laptop can request") || !strings.Contains(txt, `"Prod MySQL, read replica"`) {
		t.Errorf("list_requestable text:\n%s", txt)
	}
	flows := sc["requestable"].([]any)
	if len(flows) != 1 || flows[0].(map[string]any)["workflow_id"] != e.flow.ID {
		t.Fatalf("requestable = %v", sc["requestable"])
	}
}

func TestRequestWaitApprove(t *testing.T) {
	e := newEnv(t)
	cs := e.connect(t, "maya")

	res, sc := call(t, cs, "request_access", map[string]any{"workflow_id": e.flow.ID, "reason": "check slow queries\non orders", "duration": "30m"})
	id, _ := sc["id"].(string)
	if id == "" || sc["status"] != "pending" || sc["url"] != "http://jit/requests/"+id || sc["reason"] != `"check slow queries on orders"` {
		t.Fatalf("request_access = %v", sc)
	}
	if txt := textOf(res); !strings.Contains(txt, "PENDING") || !strings.Contains(txt, "http://jit/requests/"+id) || !strings.Contains(txt, "wait_for_access") {
		t.Errorf("request_access text:\n%s", txt)
	}

	// Waiting with a short timeout returns the request still pending.
	res, sc = call(t, cs, "wait_for_access", map[string]any{"request_id": id, "timeout_seconds": 5})
	if sc["status"] != "pending" || sc["still_waiting"] != true || !strings.Contains(textOf(res), "nobody has decided yet") {
		t.Errorf("wait (timeout) = %v\n%s", sc, textOf(res))
	}

	// Sam approves while the agent waits; wait returns approved and confirmed.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		if _, err := e.svc.Approve(context.Background(), people["sam"], id, "ok"); err != nil {
			t.Error(err)
		}
	}()
	start := time.Now()
	res, sc = call(t, cs, "wait_for_access", map[string]any{"request_id": id, "timeout_seconds": 60})
	if sc["status"] != "approved" || time.Since(start) > 20*time.Second {
		t.Fatalf("wait = %v after %s", sc, time.Since(start))
	}
	enf, _ := sc["enforcement"].(map[string]any)
	if enf["confirmed_at"] == nil || enf["confirmed_at"] == "" {
		t.Errorf("not confirmed: %v", sc["enforcement"])
	}
	if txt := textOf(res); !strings.Contains(txt, "APPROVED") || !strings.Contains(txt, "in place") || !strings.Contains(txt, "svc:mysql-prod") {
		t.Errorf("wait text:\n%s", txt)
	}

	// The approver's note reaches the model quoted.
	_, sc = call(t, cs, "get_access_request", map[string]any{"request_id": id})
	appr := sc["approvals"].([]any)[0].(map[string]any)
	if appr["actor"] != "sam@example.com" || appr["note"] != `"ok"` {
		t.Errorf("approval = %v", appr)
	}

	// Ending it early revokes.
	res, sc = call(t, cs, "cancel_access_request", map[string]any{"request_id": id, "note": "done"})
	if sc["status"] != "revoked" || !strings.Contains(textOf(res), "REVOKED") {
		t.Errorf("cancel = %v\n%s", sc, textOf(res))
	}
	// Again: already over, no error.
	_, sc = call(t, cs, "cancel_access_request", map[string]any{"request_id": id})
	if sc["status"] != "revoked" {
		t.Errorf("second cancel = %v", sc)
	}
}

func TestErrorsAndIdentity(t *testing.T) {
	e := newEnv(t)
	cs := e.connect(t, "maya")

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "request_access", Arguments: map[string]any{"workflow_id": e.flow.ID, "reason": "x", "duration": "9h"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textOf(res), "duration") {
		t.Errorf("too long: isError=%v %s", res.IsError, textOf(res))
	}

	// A duplicate names the request that already covers it.
	_, sc := call(t, cs, "request_access", map[string]any{"workflow_id": e.flow.ID, "reason": "first"})
	res, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "request_access", Arguments: map[string]any{"workflow_id": e.flow.ID, "reason": "again"}})
	if !res.IsError || !strings.Contains(textOf(res), "http://jit/requests/"+sc["id"].(string)) {
		t.Errorf("duplicate: isError=%v %s", res.IsError, textOf(res))
	}

	// Sam is not a requester: nothing to request, and he can't see Maya's request.
	sam := e.connect(t, "sam")
	res, _ = call(t, sam, "list_requestable", nil)
	if !strings.Contains(textOf(res), "nothing sam@example.com can request") {
		t.Errorf("sam's list:\n%s", textOf(res))
	}

	// An unidentified caller is refused before MCP: jitd's JSON error.
	resp, body := post(t, e.url, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.StatusCode != 401 || !strings.Contains(body, "identity_unavailable") {
		t.Errorf("anonymous: %d %s", resp.StatusCode, body)
	}

	// Answers are one JSON object, never an event stream, so proxies and
	// hosts that buffer or time out streams are not a concern.
	resp, body = post(t, e.url, "maya", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != 200 || !strings.HasPrefix(ct, "application/json") || !strings.Contains(body, `"wait_for_access"`) {
		t.Errorf("tools/list over plain HTTP: %d %s %.80s", resp.StatusCode, ct, body)
	}
}

// post sends one raw MCP message as user (nobody when empty).
func post(t *testing.T, url, user, msg string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(msg))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// A flow the policy does not use is refused at request time, and a request
// on such a flow carries the warning whatever its status.
func TestNoEffectFlow(t *testing.T) {
	e := newEnvWith(t, &fakeTS{present: true}) // empty policy: nothing gates on the attribute
	cs := e.connect(t, "maya")
	res, _ := call(t, cs, "list_requestable", nil)
	if !strings.Contains(textOf(res), "WARNING: no grant in the tailnet policy uses this flow's attribute") {
		t.Errorf("list text:\n%s", textOf(res))
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "request_access", Arguments: map[string]any{"workflow_id": e.flow.ID, "reason": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textOf(res), "would unlock nothing") || !strings.Contains(textOf(res), `"Database access (read-only)"`) {
		t.Errorf("request on a no-effect flow: isError=%v %s", res.IsError, textOf(res))
	}
	if n := len(e.svc.Requestable(context.Background(), people["maya"])); n != 1 || e.svc.Requestable(context.Background(), people["maya"])[0].ActiveRequestID != "" {
		t.Errorf("a request was filed anyway")
	}

	// The warning also follows an existing request through its statuses.
	for _, st := range []string{"pending", "approved", "revoked"} {
		txt := summarizeRequest(accessRequest{ID: "req_x", Status: st, WorkflowName: "F", Policy: &policyUse{Unreferenced: true}}, identity{})
		if !strings.Contains(txt, "WARNING: this flow is not in the tailnet policy") {
			t.Errorf("%s: no warning:\n%s", st, txt)
		}
	}
}

// The text is written for whoever is reading: an approver's agent is told
// whose request it is, not that it submitted it or has the access.
func TestViewerText(t *testing.T) {
	e := newEnv(t)
	maya, sam := e.connect(t, "maya"), e.connect(t, "sam")
	_, sc := call(t, maya, "request_access", map[string]any{"workflow_id": e.flow.ID, "reason": "x"})
	id := sc["id"].(string)

	res, _ := call(t, sam, "get_access_request", map[string]any{"request_id": id})
	txt := textOf(res)
	if !strings.Contains(txt, "by maya@example.com on maya-laptop") || !strings.Contains(txt, "This is not your request") || strings.Contains(txt, "Tell the user you submitted") || strings.Contains(txt, "wait_for_access") {
		t.Errorf("sam reading maya's pending request:\n%s", txt)
	}
	if _, err := e.svc.Approve(context.Background(), people["sam"], id, ""); err != nil {
		t.Fatal(err)
	}
	res, _ = call(t, sam, "wait_for_access", map[string]any{"request_id": id, "timeout_seconds": 5})
	if txt = textOf(res); !strings.Contains(txt, "APPROVED") || !strings.Contains(txt, "maya-laptop, not on this one") || strings.Contains(txt, "in place on this device") {
		t.Errorf("sam waiting on maya's approved request:\n%s", txt)
	}
	res, _ = call(t, maya, "get_access_request", map[string]any{"request_id": id})
	if txt = textOf(res); !strings.Contains(txt, "in place on this device") || strings.Contains(txt, " by maya") {
		t.Errorf("maya reading her own request:\n%s", txt)
	}
}

// A wait abandoned by its client stops polling. The SDK's context never
// ends for today's clients, so the server watches the HTTP request itself.
func TestWaitOutlivesClient(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 13s")
	}
	e := newEnvWith(t, &fakeTS{present: false, policy: gatedPolicy()}) // approved but never confirmed: the wait keeps reading the device
	maya := e.connect(t, "maya")
	_, sc := call(t, maya, "request_access", map[string]any{"workflow_id": e.flow.ID, "reason": "x"})
	id := sc["id"].(string)
	if _, err := e.svc.Approve(context.Background(), people["sam"], id, ""); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait_for_access","arguments":{"request_id":%q,"timeout_seconds":240}}}`, id)
	req, _ := http.NewRequestWithContext(ctx, "POST", e.url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-Test-User", "maya")
	go http.DefaultClient.Do(req) //nolint: the client leaves before the answer
	time.Sleep(time.Second)
	cancel()
	time.Sleep(500 * time.Millisecond)
	before := e.ts.reads.Load()
	time.Sleep(11 * time.Second) // the wait re-reads the device every 10s while it runs
	if after := e.ts.reads.Load(); after != before {
		t.Errorf("device read %d times after the client left (was %d); the wait kept polling", after-before, before)
	}
}

// A message over the limit is refused with 413 and jitd's error shape, not
// cut short into a JSON parse error.
func TestLargeBody(t *testing.T) {
	e := newEnv(t)
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_access","arguments":{"workflow_id":"x","reason":"` + strings.Repeat("a", maxBody) + `"}}}`
	resp, body := post(t, e.url, "maya", big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(body, "too_large") {
		t.Errorf("1 MiB+ body: %d %.120s", resp.StatusCode, body)
	}
}
