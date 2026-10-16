package jit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// fakeTS records calls and keeps attributes in memory.
type fakeTS struct {
	calls    []string
	attrs    map[string]time.Time // device|key -> expiry
	fail     map[string]error     // key -> error for Set/Delete
	groups   map[string][]string
	policyN  int
	policyEr error
	policy   tsapi.Policy  // served instead of groups when set
	delay    time.Duration // added to SetAttribute, to simulate a slow API
	// lateFail: SetAttribute applies the attribute, then reports this error
	// (a timeout or lost response after Tailscale already did it).
	lateFail error
}

func newFakeTS() *fakeTS {
	return &fakeTS{attrs: map[string]time.Time{}, fail: map[string]error{}}
}

func (f *fakeTS) SetAttribute(ctx context.Context, device, key string, value any, expiry time.Time, comment string) error {
	time.Sleep(f.delay)
	f.calls = append(f.calls, fmt.Sprintf("SET %s %s %v %s", device, key, value, expiry.UTC().Format(time.RFC3339)))
	if err := f.fail[key]; err != nil {
		return err
	}
	f.attrs[device+"|"+key] = expiry
	if f.lateFail != nil {
		err := f.lateFail
		f.lateFail = nil // only the first call
		return err
	}
	return nil
}

func (f *fakeTS) GetAttributes(ctx context.Context, device string) (tsapi.Attributes, error) {
	out := tsapi.Attributes{Attributes: map[string]any{}, Expiries: map[string]time.Time{}}
	for k, exp := range f.attrs {
		if dev, key, ok := strings.Cut(k, "|"); ok && dev == device {
			out.Attributes[key] = true
			out.Expiries[key] = exp
		}
	}
	return out, nil
}

func (f *fakeTS) DeleteAttribute(ctx context.Context, device, key string) error {
	f.calls = append(f.calls, fmt.Sprintf("DEL %s %s", device, key))
	if err := f.fail[key]; err != nil {
		return err
	}
	if _, ok := f.attrs[device+"|"+key]; !ok {
		return &tsapi.APIError{Status: http.StatusNotFound}
	}
	delete(f.attrs, device+"|"+key)
	return nil
}

func (f *fakeTS) GetPolicy(ctx context.Context) (tsapi.Policy, error) {
	f.policyN++
	if f.policyEr != nil {
		return tsapi.Policy{}, f.policyEr
	}
	if f.policy.Groups != nil || f.policy.Grants != nil || f.policy.Postures != nil {
		return f.policy, nil
	}
	return tsapi.Policy{Groups: f.groups}, nil
}

var (
	ctx   = context.Background()
	t0    = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	alice = Identity{Login: "alice@example.com", DeviceID: "nALICE", DeviceName: "alice-laptop"}
	bob   = Identity{Login: "bob@example.com", DeviceID: "nBOB", DeviceName: "bob-mac"}
	carol = Identity{Login: "carol@example.com", DeviceID: "nCAROL"}
	agent = Identity{Login: "tagged-devices", DeviceID: "nAGENT", DeviceName: "ci", Tags: []string{"tag:agent"}}
)

type harness struct {
	svc *Service
	ts  *fakeTS
	now time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "jit.db"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{ts: newFakeTS(), now: t0}
	h.ts.groups = map[string][]string{"group:sre": {"Carol@example.com"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h.svc = &Service{Store: st, TS: h.ts, Log: log, Now: func() time.Time { return h.now }}
	h.svc.PolicyCache = &PolicyCache{TS: h.ts, TTL: time.Minute, Log: log, Now: func() time.Time { return h.now }}
	return h
}

func (h *harness) workflow(t *testing.T, w Workflow) *Workflow {
	t.Helper()
	out, err := h.svc.CreateWorkflow(w)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rdpFlow(self bool) Workflow {
	return Workflow{
		Name: "RDP", Attribute: "windows_rdp", Resources: []Resource{{Name: "svc:windows-rdp", Description: "Windows jump host"}, {Name: "svc:k8-prod"}},
		Requesters: []Principal{"autogroup:member", "tag:agent"}, Approvers: []Principal{"bob@example.com", "group:sre"},
		AllowSelfApproval: self, MaxDuration: Duration(time.Hour),
	}
}

func code(err error) string {
	if err == nil {
		return ""
	}
	return AsError(err).Code
}

func TestSubmitAuthorization(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	only := h.workflow(t, Workflow{Name: "only bob", Attribute: "only_bob", Requesters: []Principal{"bob@example.com"}, Approvers: []Principal{"bob@example.com"}, AllowSelfApproval: true})
	// Bob is the only approver and may not approve himself: a request he
	// files could never be approved, so it is refused up front.
	deadEnd := h.workflow(t, Workflow{Name: "dead end", Attribute: "dead_end", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		id   Identity
		in   NewRequest
		want string
	}{
		{"member", alice, NewRequest{WorkflowID: w.ID, Reason: "x"}, ""},
		{"tagged via tag", agent, NewRequest{WorkflowID: w.ID, Reason: "x"}, ""},
		{"not requester", alice, NewRequest{WorkflowID: only.ID, Reason: "x"}, "forbidden"},
		{"email case-insensitive", Identity{Login: "BOB@example.com", DeviceID: "nB"}, NewRequest{WorkflowID: only.ID, Reason: "x"}, ""},
		{"too long", alice, NewRequest{WorkflowID: w.ID, Duration: Duration(2 * time.Hour), Reason: "x"}, "bad_request"},
		{"no reason", alice, NewRequest{WorkflowID: w.ID}, "bad_request"},
		{"no workflow", alice, NewRequest{WorkflowID: "wf_nope", Reason: "x"}, "not_found"},
		{"only approver, no self-approval", bob, NewRequest{WorkflowID: deadEnd.ID, Reason: "x"}, "conflict"},
		{"someone else can approve", alice, NewRequest{WorkflowID: deadEnd.ID, Reason: "x"}, ""},
		{"reason too long", alice, NewRequest{WorkflowID: w.ID, Reason: strings.Repeat("x", MaxNoteLen+1)}, "bad_request"},
	} {
		r, err := h.svc.Submit(ctx, tc.id, tc.in)
		if code(err) != tc.want {
			t.Errorf("%s: err = %v, want code %q", tc.name, err, tc.want)
		}
		if err == nil && (r.Status != StatusPending || r.TargetDeviceID != tc.id.DeviceID || r.Duration != Duration(time.Hour) && tc.in.Duration == 0) {
			t.Errorf("%s: request = %+v", tc.name, r)
		}
	}
	if len(h.ts.calls) != 0 {
		t.Errorf("submit must not call the API: %v", h.ts.calls)
	}
}

func TestAutogroupMemberExcludesTagged(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "m", Attribute: "m", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	if _, err := h.svc.Submit(context.Background(), agent, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
		t.Fatalf("tagged device matched autogroup:member: %v", err)
	}
}

func TestApproveSetsAttributes(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	ctx := context.Background()
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(30 * time.Minute), Reason: "migration"})
	if err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(2 * time.Minute)
	got, err := h.svc.Approve(ctx, bob, r.ID, "ok")
	if err != nil {
		t.Fatal(err)
	}
	exp := h.now.Add(30 * time.Minute).Format(time.RFC3339)
	want := []string{"SET nALICE custom:jit_windows_rdp true " + exp}
	if fmt.Sprint(h.ts.calls) != fmt.Sprint(want) {
		t.Errorf("calls = %v\nwant    %v", h.ts.calls, want)
	}
	if got.Status != StatusApproved || got.ExpiresAt.Format(time.RFC3339) != exp || len(got.Attributes) != 1 || got.Attribute != "custom:jit_windows_rdp" || len(got.Resources) != 2 {
		t.Errorf("approved request = %+v", got)
	}
	if last := got.Timeline[len(got.Timeline)-1]; last.Type != "approved" || last.Actor != "bob@example.com" {
		t.Errorf("timeline = %+v", got.Timeline)
	}
}

func TestApproveAuthorization(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		self  bool
		actor Identity
		want  string
	}{
		{"approver", false, bob, ""},
		{"group approver", false, carol, ""},
		{"stranger (cannot even see it)", false, Identity{Login: "eve@example.com", DeviceID: "nEVE"}, "not_found"},
		{"self not allowed", false, alice, "forbidden"},
		{"self allowed but not approver", true, alice, "forbidden"},
	} {
		h := newHarness(t)
		w := h.workflow(t, rdpFlow(tc.self))
		r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
		_, err := h.svc.Approve(ctx, tc.actor, r.ID, "")
		if code(err) != tc.want {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}

	// Self-approval when the requester is also an approver.
	for _, self := range []bool{false, true} {
		h := newHarness(t)
		w := h.workflow(t, rdpFlow(self))
		r, _ := h.svc.Submit(ctx, bob, NewRequest{WorkflowID: w.ID, Reason: "x"})
		_, err := h.svc.Approve(ctx, bob, r.ID, "")
		if (err == nil) != self {
			t.Errorf("self-approval allowed=%v: err = %v", self, err)
		}
	}

	// Approving twice conflicts.
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, bob, r.ID, "")
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); code(err) != "conflict" {
		t.Errorf("second approve: %v", err)
	}
}

func TestApproveFailures(t *testing.T) {
	ctx := context.Background()

	// The attribute cannot be set: stays pending, failure recorded.
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	h.ts.fail["custom:jit_windows_rdp"] = errors.New("403 forbidden")
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if code(err) != "tailscale_api_error" || got == nil || got.Status != StatusPending || got.LastError == "" {
		t.Fatalf("total failure: err=%v req=%+v", err, got)
	}
	if last := got.Timeline[len(got.Timeline)-1]; last.Type != "approve_failed" {
		t.Errorf("timeline = %+v", got.Timeline)
	}
	stored, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if stored.Status != StatusPending || len(stored.Timeline) != 2 {
		t.Errorf("stored after failure = %+v", stored)
	}

	// Retry after the API recovers succeeds.
	delete(h.ts.fail, "custom:jit_windows_rdp")
	if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || got.Status != StatusApproved {
		t.Fatalf("retry: %v %+v", err, got)
	}

}

func TestDecline(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	ctx := context.Background()
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if _, err := h.svc.Decline(ctx, alice, r.ID, ""); code(err) != "forbidden" {
		t.Errorf("requester decline: %v", err)
	}
	got, err := h.svc.Decline(ctx, bob, r.ID, "not today")
	if err != nil || got.Status != StatusDeclined {
		t.Fatalf("decline: %v %+v", err, got)
	}
	if len(h.ts.calls) != 0 {
		t.Errorf("decline called the API: %v", h.ts.calls)
	}
}

func TestOneFlowPerAttributeAndRevoke(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "one", Attribute: "windows_rdp", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	// A second flow for the same attribute is refused: revoking one would
	// silently keep the other's access.
	if _, err := h.svc.CreateWorkflow(Workflow{Name: "two", Attribute: "custom:jit_windows_rdp", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}}); code(err) != "conflict" {
		t.Errorf("duplicate attribute: %v", err)
	}
	other := h.workflow(t, Workflow{Name: "other", Attribute: "other", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	upd := *other
	upd.Attribute = "windows_rdp"
	if _, err := h.svc.UpdateWorkflow(other.ID, upd); code(err) != "conflict" {
		t.Errorf("update onto a taken attribute: %v", err)
	}
	upd = *w
	upd.Description = "same attribute, edited"
	if _, err := h.svc.UpdateWorkflow(w.ID, upd); err != nil {
		t.Errorf("editing a flow must not collide with itself: %v", err)
	}

	ctx := context.Background()
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(10 * time.Minute), Reason: "a"})
	h.svc.Approve(ctx, bob, r.ID, "")
	h.ts.calls = nil
	if _, err := h.svc.Revoke(ctx, Identity{Login: "eve@example.com", DeviceID: "nEVE"}, r.ID, ""); code(err) != "not_found" {
		t.Errorf("stranger revoke: %v", err)
	}
	got, err := h.svc.Revoke(ctx, alice, r.ID, "done")
	if err != nil || got.Status != StatusRevoked {
		t.Fatalf("revoke: %v %+v", err, got)
	}
	if fmt.Sprint(h.ts.calls) != "[DEL nALICE custom:jit_windows_rdp]" {
		t.Errorf("revoke calls = %v", h.ts.calls)
	}
	if len(h.ts.attrs) != 0 {
		t.Errorf("attributes left: %v", h.ts.attrs)
	}
	if _, err := h.svc.Revoke(ctx, bob, r.ID, ""); code(err) != "conflict" {
		t.Errorf("double revoke: %v", err)
	}
}

func TestRevokeFailureKeepsApproved(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "one", Attribute: "windows_rdp", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	ctx := context.Background()
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "a"})
	h.svc.Approve(ctx, bob, r.ID, "")
	h.ts.fail["custom:jit_windows_rdp"] = errors.New("503")
	got, err := h.svc.Revoke(ctx, bob, r.ID, "")
	if code(err) != "tailscale_api_error" || got.Status != StatusApproved {
		t.Fatalf("revoke failure: %v %+v", err, got)
	}
	delete(h.ts.fail, "custom:jit_windows_rdp")
	if got, err := h.svc.Revoke(ctx, bob, r.ID, ""); err != nil || got.Status != StatusRevoked {
		t.Fatalf("revoke retry: %v %+v", err, got)
	}
}

func TestExpireDue(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	ctx := context.Background()
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(5 * time.Minute), Reason: "a"})
	b, _ := h.svc.Submit(ctx, carol, NewRequest{WorkflowID: w.ID, Duration: Duration(30 * time.Minute), Reason: "b"})
	h.svc.Approve(ctx, bob, a.ID, "")
	h.svc.Approve(ctx, bob, b.ID, "")
	h.ts.calls = nil

	h.now = t0.Add(5 * time.Minute)
	if n := h.svc.ExpireDue(); n != 1 {
		t.Fatalf("expired %d, want 1", n)
	}
	ga, _ := h.svc.GetRequest(ctx, alice, a.ID)
	gb, _ := h.svc.GetRequest(ctx, carol, b.ID) // alice may not see carol's request
	if ga.Status != StatusExpired || gb.Status != StatusApproved {
		t.Errorf("statuses = %s %s", ga.Status, gb.Status)
	}
	if len(h.ts.calls) != 0 {
		t.Errorf("expiry called the API: %v", h.ts.calls)
	}
}

func TestRequestable(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	h.workflow(t, Workflow{Name: "sre only", Attribute: "db", Requesters: []Principal{"group:sre"}, Approvers: []Principal{"bob@example.com"}})
	ctx := context.Background()

	if got := h.svc.Requestable(ctx, alice); len(got) != 1 || got[0].WorkflowID != w.ID || got[0].Attribute != "custom:jit_windows_rdp" || fmt.Sprint(resourceNames(got[0].Resources)) != "[svc:windows-rdp svc:k8-prod]" {
		t.Errorf("alice requestable = %+v", got)
	}
	if got := h.svc.Requestable(ctx, carol); len(got) != 2 || got[0].WorkflowName != "RDP" || got[1].WorkflowName != "sre only" {
		t.Errorf("carol (group:sre) requestable = %+v", got)
	}

	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	got := h.svc.Requestable(ctx, alice)
	if got[0].ActiveRequestID != r.ID || got[0].ActiveStatus != StatusPending {
		t.Errorf("active marks = %+v", got)
	}
}

func TestGroupCache(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.svc.PolicyCache.Groups(ctx)
	h.svc.PolicyCache.Groups(ctx)
	if h.ts.policyN != 1 {
		t.Errorf("policy fetched %d times within TTL", h.ts.policyN)
	}
	h.now = t0.Add(2 * time.Minute)
	h.ts.policyEr = errors.New("403")
	if g, err := h.svc.PolicyCache.Groups(ctx); err != nil || len(g["group:sre"]) != 1 {
		t.Errorf("stale groups on error: %v %v", g, err)
	}

	// A failure is remembered: callers within the backoff don't refetch.
	n := h.ts.policyN
	h.svc.PolicyCache.Groups(ctx)
	h.svc.PolicyCache.Groups(ctx)
	if h.ts.policyN != n {
		t.Errorf("refetched %d times within the failure backoff", h.ts.policyN-n)
	}
	h.now = h.now.Add(failureBackoff + time.Second)
	h.ts.policyEr = nil
	h.svc.PolicyCache.Groups(ctx)
	if h.ts.policyN != n+1 {
		t.Errorf("did not retry after the backoff")
	}

	// No cache and a failing fetch: group principals don't match, others still do.
	h2 := newHarness(t)
	h2.ts.policyEr = errors.New("403")
	if h2.svc.matches(ctx, []Principal{"group:sre"}, carol) {
		t.Error("group matched without policy")
	}
	if !h2.svc.matches(ctx, []Principal{"group:sre", "carol@example.com"}, carol) {
		t.Error("email principal should still match")
	}
}

func TestDeleteWorkflowWithActiveRequests(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	ctx := context.Background()
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err := h.svc.DeleteWorkflow(w.ID); code(err) != "conflict" {
		t.Fatalf("delete with pending: %v", err)
	}
	h.svc.Decline(ctx, bob, r.ID, "not needed")
	if err := h.svc.DeleteWorkflow(w.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPolicySnippet(t *testing.T) {
	h := newHarness(t)
	h.workflow(t, rdpFlow(false))
	h.workflow(t, Workflow{Name: "bare", Attribute: "bare", Requesters: []Principal{"group:sre"}, Approvers: []Principal{"bob@example.com"}})
	s := h.svc.PolicySnippet("tag:jit")
	for _, want := range []string{
		`"posture:jit_windows_rdp": ["custom:jit_windows_rdp == true"]`,
		`"posture:jit_bare": ["custom:jit_bare == true"]`,
		`"dst": ["svc:windows-rdp", "svc:k8-prod"]`,
		`"srcPosture": ["posture:jit_windows_rdp"]`,
		`"src": ["autogroup:member", "tag:agent"]`,
		`"src": ["group:sre"]`,
		`"dst": ["TODO: what this flow gives access to`,
		`"dst": ["tag:jit"]`,
		`// "app": {"tailscale.com/cap/pam"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("snippet missing %s\n%s", want, s)
		}
	}
	if strings.Count(s, `"srcPosture"`) != 2 {
		t.Errorf("want exactly 2 gated grants:\n%s", s)
	}
}

func TestCheckedSnippet(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.workflow(t, rdpFlow(false))
	h.workflow(t, Workflow{Name: "K8s", Attribute: "k8s_ro", Resources: []Resource{{Name: "svc:k8s"}}, Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	h.ts.policy = tsapi.Policy{
		Groups:   h.ts.groups,
		Postures: map[string][]string{"posture:jit_windows_rdp": {"custom:jit_windows_rdp == true"}},
		Grants:   []tsapi.Grant{{Src: []string{"autogroup:member"}, Dst: []string{"svc:windows-rdp"}, SrcPosture: []string{"posture:jit_windows_rdp"}}},
	}
	s, err := h.svc.CheckedSnippet(ctx, "tag:jit", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"posture:jit_windows_rdp": ["custom:jit_windows_rdp == true"] // already in your policy`,
		`"posture:jit_k8s_ro": ["custom:jit_k8s_ro == true"], // NEW: not in your policy yet`,
		`// Approval flow "RDP" already in your policy`,
		`// Your grant's dst differs from the flow's list`,
		`// Approval flow "K8s" NEW: not in your policy yet`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marked snippet missing %s\n%s", want, s)
		}
	}
	s, _ = h.svc.CheckedSnippet(ctx, "tag:jit", true)
	if strings.Contains(s, "posture:jit_windows_rdp\": [") || strings.Contains(s, `"RDP"`) || !strings.Contains(s, "posture:jit_k8s_ro") || !strings.Contains(s, `"tag:jit"`) {
		t.Errorf("only-missing snippet:\n%s", s)
	}
	// Unreadable policy (and nothing cached): unmarked, error returned.
	h2 := newHarness(t)
	h2.workflow(t, rdpFlow(false))
	h2.ts.policyEr = errors.New("403")
	s, err = h2.svc.CheckedSnippet(ctx, "tag:jit", true)
	if err == nil || strings.Contains(s, "already in your policy") || !strings.Contains(s, "posture:jit_windows_rdp") {
		t.Errorf("unreadable policy: err=%v\n%s", err, s)
	}
}

func TestPolicyUse(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	w := h.workflow(t, rdpFlow(false))
	h.ts.policy = tsapi.Policy{
		Groups:   h.ts.groups,
		Postures: map[string][]string{"posture:jit_windows_rdp": {"custom:jit_windows_rdp  ==  true"}},
		Grants: []tsapi.Grant{
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:windows-rdp", "tag:rdp-hosts"}, SrcPosture: []string{"posture:jit_windows_rdp"}},
			{Src: []string{"autogroup:member"}, Dst: []string{"svc:k8-prod"}}, // standing, not gated
		},
	}
	u := h.svc.PolicyUse(ctx, w)
	if !u.Defined || u.Unreferenced || fmt.Sprint(u.Grants) != "[svc:windows-rdp tag:rdp-hosts]" || fmt.Sprint(u.Missing) != "[svc:k8-prod]" || fmt.Sprint(u.Extra) != "[tag:rdp-hosts]" || u.OK() {
		t.Errorf("drift: %+v", u)
	}
	if p := u.Problems(); len(p) != 2 {
		t.Errorf("problems: %v", p)
	}

	// Agreeing policy.
	upd := *w
	upd.Resources = []Resource{{Name: "svc:windows-rdp"}, {Name: "tag:rdp-hosts"}}
	w2, _ := h.svc.UpdateWorkflow(w.ID, upd)
	if u := h.svc.PolicyUse(ctx, w2); !u.OK() {
		t.Errorf("should agree: %+v", u)
	}

	// Posture missing and no grant: unlocks nothing.
	bare := h.workflow(t, Workflow{Name: "bare", Attribute: "bare", Resources: []Resource{{Name: "svc:x"}}, Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	u = h.svc.PolicyUse(ctx, bare)
	if u.Defined || !u.Unreferenced || len(u.Missing) != 0 || u.OK() || len(u.Problems()) != 1 {
		t.Errorf("unreferenced: %+v %v", u, u.Problems())
	}

	// Unreadable policy: unknown, not a verdict.
	h2 := newHarness(t)
	h2.ts.policyEr = errors.New("403")
	w3 := h2.workflow(t, rdpFlow(false))
	if u := h2.svc.PolicyUse(ctx, w3); u.Error == "" || u.OK() || u.Unreferenced {
		t.Errorf("error case: %+v", u)
	}
}

// P0 rules: roles, visibility, cancel, duplicate guard and pending timeout.
func TestRolesAndVisibility(t *testing.T) {
	h := newHarness(t)
	h.svc.Admins = []Principal{"group:sre"} // carol
	w := h.workflow(t, rdpFlow(false))
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	dave := Identity{Login: "dave@example.com", DeviceID: "nDAVE"}
	for _, tc := range []struct {
		who  Identity
		see  bool
		name string
	}{{alice, true, "requester"}, {bob, true, "approver"}, {carol, true, "admin"}, {dave, false, "stranger"}} {
		if _, err := h.svc.GetRequest(ctx, tc.who, r.ID); (err == nil) != tc.see {
			t.Errorf("%s GetRequest: err=%v, want visible=%v", tc.name, err, tc.see)
		}
		n := len(h.svc.ListRequests(ctx, ListFilter{Viewer: tc.who}))
		if (n == 1) != tc.see {
			t.Errorf("%s ListRequests: %d rows, want visible=%v", tc.name, n, tc.see)
		}
	}
	if n := len(h.svc.ListRequests(ctx, ListFilter{Viewer: bob, Scope: ScopeMine})); n != 0 {
		t.Errorf("bob mine = %d, want 0", n)
	}
	if n := len(h.svc.ListRequests(ctx, ListFilter{Viewer: bob, Scope: ScopeApprovals})); n != 1 {
		t.Errorf("bob approvals = %d, want 1", n)
	}
	if !h.svc.IsAdmin(ctx, carol) || h.svc.IsAdmin(ctx, alice) {
		t.Error("IsAdmin wrong")
	}
	h.svc.Admins = nil
	if h.svc.IsAdmin(ctx, carol) {
		t.Error("no admins configured must mean nobody is an admin")
	}
}

func TestCancelAndDuplicate(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	// A second live request for the same flow and device points at the first.
	_, err = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "again"})
	if e := AsError(err); e.Code != "conflict" || e.RequestID != r.ID {
		t.Fatalf("duplicate submit: %v (request %q)", err, e.RequestID)
	}
	// Only the requester may cancel; approvers decline instead.
	if _, err := h.svc.Cancel(ctx, bob, r.ID, ""); code(err) != "forbidden" {
		t.Errorf("bob cancel: %v", err)
	}
	got, err := h.svc.Cancel(ctx, alice, r.ID, "typo")
	if err != nil || got.Status != StatusCancelled || got.Timeline[len(got.Timeline)-1].Type != "cancelled" {
		t.Fatalf("cancel: %v %+v", err, got)
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); code(err) != "conflict" {
		t.Errorf("approve after cancel: %v", err)
	}
	// Cancelled is not live, so a new request goes through.
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "again"}); err != nil {
		t.Errorf("resubmit after cancel: %v", err)
	}
	if len(h.ts.calls) != 0 {
		t.Errorf("cancel made API calls: %v", h.ts.calls)
	}
}

func TestPendingTimeout(t *testing.T) {
	h := newHarness(t)
	w := rdpFlow(false)
	w.ApprovalTimeout = Duration(2 * time.Hour)
	wf := h.workflow(t, w)
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: wf.ID, Duration: Duration(time.Hour), Reason: "x"})
	h.now = t0.Add(119 * time.Minute)
	if n := h.svc.ExpireDue(); n != 0 {
		t.Fatalf("expired %d before the timeout", n)
	}
	h.now = t0.Add(2 * time.Hour)
	if n := h.svc.ExpireDue(); n != 1 {
		t.Fatalf("expired %d at the timeout, want 1", n)
	}
	got, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if got.Status != StatusExpired || !strings.Contains(got.Timeline[len(got.Timeline)-1].Note, "no decision") {
		t.Errorf("after timeout: %+v", got)
	}
}

func TestQuorumAndVerification(t *testing.T) {
	h := newHarness(t)
	w := rdpFlow(false)
	w.ApprovalsRequired = 2 // bob and group:sre (carol)
	wf := h.workflow(t, w)
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: wf.ID, Duration: Duration(time.Hour), Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ApprovalsRequired != 2 {
		t.Fatalf("request snapshot approvals_required = %d", r.ApprovalsRequired)
	}
	// First vote: still pending, nothing written.
	got, err := h.svc.Approve(ctx, bob, r.ID, "ok")
	if err != nil || got.Status != StatusPending || len(got.Approvals) != 1 || got.Timeline[len(got.Timeline)-1].Type != "approval" {
		t.Fatalf("first approval: %v %+v", err, got)
	}
	if len(h.ts.calls) != 0 {
		t.Fatalf("attribute written after one of two approvals: %v", h.ts.calls)
	}
	// Same person again: no change, no error.
	got, err = h.svc.Approve(ctx, bob, r.ID, "again")
	if err != nil || len(got.Approvals) != 1 {
		t.Fatalf("repeat approval: %v %+v", err, got)
	}
	if p := h.svc.Permissions(ctx, bob, got); p.Approve || !strings.Contains(p.Why, "already") {
		t.Errorf("bob may approve twice: %+v", p)
	}
	// Second distinct approver: granted and read back from the device.
	got, err = h.svc.Approve(ctx, carol, r.ID, "")
	if err != nil || got.Status != StatusApproved || len(got.Approvals) != 2 {
		t.Fatalf("second approval: %v %+v", err, got)
	}
	if got.Enforcement.ConfirmedAt == nil || got.Enforcement.Error != "" {
		t.Errorf("approval not confirmed by read-back: %+v", got.Enforcement)
	}
	// Revoke deletes the attribute and confirms it gone.
	got, err = h.svc.Revoke(ctx, alice, r.ID, "")
	if err != nil || got.Enforcement.RemovedAt == nil {
		t.Fatalf("revoke not confirmed: %v %+v", err, got.Enforcement)
	}
}

func TestExpiryRemovalVerified(t *testing.T) {
	h := newHarness(t)
	wf := h.workflow(t, rdpFlow(false))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: wf.ID, Duration: Duration(10 * time.Minute), Reason: "x"})
	h.svc.Approve(ctx, bob, r.ID, "")
	h.now = t0.Add(10 * time.Minute)
	h.svc.ExpireDue()
	got, _ := h.svc.GetRequest(ctx, alice, r.ID)
	// The fake keeps the attribute until deleted, like Tailscale does for a
	// minute or so: not yet confirmed gone.
	if got.Status != StatusExpired || got.Enforcement.RemovedAt != nil {
		t.Fatalf("right after expiry: %s removed=%v", got.Status, got.Enforcement.RemovedAt)
	}
	for k := range h.ts.attrs { // Tailscale drops it
		delete(h.ts.attrs, k)
	}
	h.now = h.now.Add(time.Minute)
	h.svc.ExpireDue()
	got, _ = h.svc.GetRequest(ctx, alice, r.ID)
	if got.Enforcement.RemovedAt == nil {
		t.Errorf("removal not confirmed once the attribute is gone: %+v", got.Enforcement)
	}
}

func TestDisabledFlowAndDeclineReason(t *testing.T) {
	h := newHarness(t)
	wf := h.workflow(t, rdpFlow(false))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: wf.ID, Duration: Duration(time.Hour), Reason: "x"})
	if _, err := h.svc.Decline(ctx, bob, r.ID, "  "); code(err) != "bad_request" {
		t.Errorf("decline without reason: %v", err)
	}
	wf.Disabled = true
	if _, err := h.svc.UpdateWorkflow(wf.ID, *wf); err != nil {
		t.Fatal(err)
	}
	if n := len(h.svc.Requestable(ctx, alice)); n != 0 {
		t.Errorf("disabled flow still requestable (%d)", n)
	}
	if _, err := h.svc.Submit(ctx, carol, NewRequest{WorkflowID: wf.ID, Duration: Duration(time.Hour), Reason: "x"}); code(err) != "conflict" {
		t.Errorf("submit on disabled flow: %v", err)
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); code(err) != "conflict" {
		t.Errorf("approve on disabled flow: %v", err)
	}
	if got, err := h.svc.Decline(ctx, bob, r.ID, "flow retired"); err != nil || got.Status != StatusDeclined {
		t.Errorf("decline on disabled flow should still work: %v", err)
	}
}

func TestWorkflowDefaults(t *testing.T) {
	h := newHarness(t)
	w := rdpFlow(false)
	w.MaxDuration = Duration(30 * time.Minute)
	wf := h.workflow(t, w)
	if wf.ApprovalsRequired != 1 || wf.DefaultDuration != Duration(30*time.Minute) || wf.ApprovalTimeout != DefaultApprovalTimeout {
		t.Errorf("defaults: %+v", wf)
	}
	w.ApprovalsRequired = 3
	w.Approvers = []Principal{"bob@example.com", "carol@example.com"}
	if _, err := h.svc.CreateWorkflow(w); code(err) != "bad_request" {
		t.Errorf("quorum above named approvers accepted: %v", err)
	}
}

// VerifyNow by an approver who is neither requester nor admin used to take
// Store.mu twice (CanView reads the store inside the transaction) and hang
// the process. Run it with a deadline so a regression fails instead of
// hanging the suite.
func TestVerifyNowByApproverDoesNotDeadlock(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.svc.VerifyNow(ctx, carol, r.ID) // carol: group:sre approver
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("VerifyNow as approver: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VerifyNow as approver deadlocked")
	}
	// A stranger still gets 404, and the store keeps working afterwards.
	if _, err := h.svc.VerifyNow(ctx, Identity{Login: "dave@example.com", DeviceID: "nD"}, r.ID); code(err) != "not_found" {
		t.Fatalf("stranger: err = %v, want not_found", err)
	}
	if _, err := h.svc.GetRequest(ctx, alice, r.ID); err != nil {
		t.Fatal(err)
	}
}

// Admins decline other people's requests; nobody declines their own; only
// the requester cancels.
func TestDeclineAndCancelRoles(t *testing.T) {
	h := newHarness(t)
	h.svc.Admins = []Principal{"root@example.com"}
	root := Identity{Login: "root@example.com", DeviceID: "nROOT"}
	w := h.workflow(t, rdpFlow(false))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if _, err := h.svc.Decline(ctx, alice, r.ID, "no"); code(err) != "forbidden" {
		t.Errorf("decline own: %v", err)
	}
	if _, err := h.svc.Cancel(ctx, root, r.ID, ""); code(err) != "forbidden" {
		t.Errorf("admin cancel: %v", err)
	}
	if _, err := h.svc.Decline(ctx, root, r.ID, "policy"); err != nil {
		t.Errorf("admin decline: %v", err)
	}
	r2, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if _, err := h.svc.Decline(ctx, bob, r2.ID, strings.Repeat("x", MaxNoteLen+1)); code(err) != "bad_request" {
		t.Errorf("long note: %v", err)
	}
	if _, err := h.svc.Cancel(ctx, alice, r2.ID, ""); err != nil {
		t.Errorf("own cancel: %v", err)
	}
}

// A verification that finds nothing new must not count as a change, or every
// open page would reload on every expiry tick.
func TestNoopUpdateIsNotAChange(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(true))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if got.Enforcement.ConfirmedAt == nil {
		t.Fatal("approve should have confirmed the attribute")
	}
	before := h.svc.Store.Changes()
	for i := 0; i < 3; i++ {
		h.now = h.now.Add(time.Minute) // checked_at moves; nothing else does
		if _, err := h.svc.VerifyNow(ctx, alice, r.ID); err != nil {
			t.Fatal(err)
		}
	}
	if h.svc.Store.Changes() != before {
		t.Fatalf("no-op verify bumped changes: %d -> %d", before, h.svc.Store.Changes())
	}
	got, _ = h.svc.GetRequest(ctx, alice, r.ID)
	if got.Enforcement.CheckedAt == nil || !got.Enforcement.CheckedAt.Equal(h.now) {
		t.Fatalf("checked_at not recorded: %v", got.Enforcement.CheckedAt)
	}
}

// Requests are approved against the flow as it is now.
func TestApproveUsesCurrentFlow(t *testing.T) {
	ctx := context.Background()
	member := []Principal{"autogroup:member"}

	// Attribute changed after submit: refused, and the UI says why.
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "f", Attribute: "prod_db", Requesters: member, Approvers: []Principal{"bob@example.com"}, MaxDuration: Duration(30 * 24 * time.Hour)})
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(30 * 24 * time.Hour), Reason: "x"})
	upd := *w
	upd.Attribute = "staging_db"
	upd.MaxDuration = Duration(time.Hour)
	h.svc.UpdateWorkflow(w.ID, upd)
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); code(err) != "conflict" || len(h.ts.calls) != 0 {
		t.Errorf("attribute changed: err=%v calls=%v", err, h.ts.calls)
	}
	if a := h.svc.Permissions(ctx, bob, r); a.Approve || !strings.Contains(a.Why, "custom:jit_staging_db") {
		t.Errorf("permissions: %+v", a)
	}

	// Max duration lowered: capped. Quorum raised: the higher one applies.
	h = newHarness(t)
	w = h.workflow(t, Workflow{Name: "g", Attribute: "g", Requesters: member, Approvers: []Principal{"bob@example.com", "group:sre"}, MaxDuration: Duration(8 * time.Hour)})
	r, _ = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(8 * time.Hour), Reason: "x"})
	upd = *w
	upd.MaxDuration, upd.ApprovalsRequired = Duration(time.Hour), 2
	h.svc.UpdateWorkflow(w.ID, upd)
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil || got.Status != StatusPending || got.ApprovalsRequired != 2 {
		t.Fatalf("raised quorum: %v %+v", err, got)
	}
	got, err = h.svc.Approve(ctx, carol, r.ID, "")
	if err != nil || got.Status != StatusApproved || got.Duration != Duration(time.Hour) || !got.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("capped duration: %v %+v", err, got)
	}

	// Requester removed from the flow: refused.
	h = newHarness(t)
	w = h.workflow(t, Workflow{Name: "h", Attribute: "h", Requesters: member, Approvers: []Principal{"bob@example.com"}})
	r, _ = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	upd = *w
	upd.Requesters = []Principal{"carol@example.com"}
	h.svc.UpdateWorkflow(w.ID, upd)
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); code(err) != "conflict" {
		t.Errorf("requester removed: %v", err)
	}

	// Disabled flow: no Approve button.
	h = newHarness(t)
	w = h.workflow(t, Workflow{Name: "i", Attribute: "i", Requesters: member, Approvers: []Principal{"bob@example.com"}})
	r, _ = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	upd = *w
	upd.Disabled = true
	h.svc.UpdateWorkflow(w.ID, upd)
	if a := h.svc.Permissions(ctx, bob, r); a.Approve || !strings.Contains(a.Why, "disabled") || !a.Decline {
		t.Errorf("disabled: %+v", a)
	}
}

func TestQuorumReachable(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	two := h.workflow(t, Workflow{Name: "two", Attribute: "two", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"alice@example.com", "bob@example.com"}, ApprovalsRequired: 2})
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: two.ID, Reason: "x"}); code(err) != "conflict" {
		t.Errorf("alice is one of the two approvers: %v", err)
	}
	if _, err := h.svc.Submit(ctx, carol, NewRequest{WorkflowID: two.ID, Reason: "x"}); err != nil {
		t.Errorf("carol has two other approvers: %v", err)
	}
	// Groups are resolved: group:sre is only carol, so alice + group:sre
	// cannot give alice 2 approvals, but can give dave 2.
	grp := h.workflow(t, Workflow{Name: "grp", Attribute: "grp", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"alice@example.com", "group:sre"}, ApprovalsRequired: 2})
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: grp.ID, Reason: "x"}); code(err) != "conflict" {
		t.Errorf("group too small: %v", err)
	}
	dave := Identity{Login: "dave@example.com", DeviceID: "nDAVE"}
	if _, err := h.svc.Submit(ctx, dave, NewRequest{WorkflowID: grp.ID, Reason: "x"}); err != nil {
		t.Errorf("dave has alice and carol: %v", err)
	}
	// carol is the whole group: the flow is not even offered to her.
	only := h.workflow(t, Workflow{Name: "only sre", Attribute: "only_sre", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"group:sre"}})
	for _, f := range h.svc.Requestable(ctx, carol) {
		if f.WorkflowID == only.ID {
			t.Error("flow nobody else can approve is offered to carol")
		}
	}
	// A group that cannot be resolved (and nothing cached) is assumed big enough.
	h2 := newHarness(t)
	h2.ts.policyEr = errors.New("503")
	if !h2.svc.quorumReachable(ctx, grp, alice) {
		t.Error("unresolvable group should be assumed reachable")
	}
}

// A tagged approver cannot vote twice by renaming its device.
func TestTaggedApproverVotesOnce(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "t", Attribute: "t", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"tag:approver"}, ApprovalsRequired: 2})
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	bot := Identity{Login: "tagged-devices", DeviceID: "nBOT", DeviceName: "bot-1", Tags: []string{"tag:approver"}}
	h.svc.Approve(ctx, bot, r.ID, "")
	bot.DeviceName = "bot-renamed"
	got, err := h.svc.Approve(ctx, bot, r.ID, "")
	if err != nil || got.Status != StatusPending || len(got.Approvals) != 1 {
		t.Errorf("renamed bot voted twice: %v %+v", err, got)
	}
	other := Identity{Login: "tagged-devices", DeviceID: "nBOT2", DeviceName: "bot-2", Tags: []string{"tag:approver"}}
	if got, _ := h.svc.Approve(ctx, other, r.ID, ""); got.Status != StatusApproved {
		t.Errorf("second device should complete the quorum: %+v", got)
	}
}

// API calls must not hold the store lock: reads stay fast while the
// Tailscale API is slow.
func TestSlowAPIDoesNotBlockReads(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.ts.delay = 300 * time.Millisecond
	done := make(chan struct{})
	go func() { h.svc.Approve(ctx, bob, r.ID, ""); close(done) }()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	h.svc.Store.Changes()
	h.svc.ListWorkflows()
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("reads blocked for %v behind a slow API call", d)
	}
	<-done
}

// Votes are re-checked against the flow as it is now, and the quorum is the
// flow's current one.
func TestVotesFollowTheFlow(t *testing.T) {
	ctx := context.Background()
	member := []Principal{"autogroup:member"}
	dave := Identity{Login: "dave@example.com", DeviceID: "nDAVE"}

	// bob votes, is removed as approver, then carol votes: still 1 of 2.
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "f", Attribute: "f", Requesters: member, Approvers: []Principal{"bob@example.com", "carol@example.com", "dave@example.com"}, ApprovalsRequired: 2})
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, bob, r.ID, "")
	upd := *w
	upd.Approvers = []Principal{"carol@example.com", "dave@example.com"}
	h.svc.UpdateWorkflow(w.ID, upd)
	got, _ := h.svc.Approve(ctx, carol, r.ID, "")
	if got.Status != StatusPending {
		t.Fatalf("removed approver's vote counted: %+v", got)
	}
	if got, _ = h.svc.Approve(ctx, dave, r.ID, ""); got.Status != StatusApproved {
		t.Errorf("two current approvers should grant: %+v", got)
	}

	// The requester self-voted, then self-approval was turned off.
	h = newHarness(t)
	w = h.workflow(t, Workflow{Name: "g", Attribute: "g", Requesters: member, Approvers: member, AllowSelfApproval: true, ApprovalsRequired: 2})
	r, _ = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, alice, r.ID, "")
	upd = *w
	upd.AllowSelfApproval = false
	h.svc.UpdateWorkflow(w.ID, upd)
	if got, _ := h.svc.Approve(ctx, bob, r.ID, ""); got.Status != StatusPending {
		t.Errorf("self-vote counted after self-approval was turned off: %+v", got)
	}

	// Quorum lowered after one vote: the pending request follows, and the
	// approver who already voted can finish it.
	h = newHarness(t)
	w = h.workflow(t, Workflow{Name: "q", Attribute: "q", Requesters: member, Approvers: []Principal{"bob@example.com", "carol@example.com", "dave@example.com"}, ApprovalsRequired: 3})
	r, _ = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, bob, r.ID, "")
	upd = *w
	upd.ApprovalsRequired = 1
	h.svc.UpdateWorkflow(w.ID, upd)
	cur, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if cur.ApprovalsRequired != 1 {
		t.Errorf("pending request kept the old quorum: %d", cur.ApprovalsRequired)
	}
	if a := h.svc.Permissions(ctx, bob, cur); !a.Approve {
		t.Errorf("bob should be able to finish it: %+v", a)
	}
	if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || got.Status != StatusApproved {
		t.Errorf("finish after lowering: %v %+v", err, got)
	}

	// Attribute changed: pending requests expire, so a new one can be filed.
	h = newHarness(t)
	w = h.workflow(t, Workflow{Name: "a", Attribute: "old", Requesters: member, Approvers: []Principal{"bob@example.com"}})
	r, _ = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	upd = *w
	upd.Attribute = "new"
	h.svc.UpdateWorkflow(w.ID, upd)
	if cur, _ := h.svc.GetRequest(ctx, alice, r.ID); cur.Status != StatusExpired {
		t.Errorf("pending request should expire on attribute change: %s", cur.Status)
	}
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "again"}); err != nil {
		t.Errorf("new request after the change: %v", err)
	}
}

// A grant whose API call fails after Tailscale applied it must not leave the
// attribute on the device.
func TestApproveCleansUpAfterAmbiguousFailure(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	w := h.workflow(t, rdpFlow(false))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.ts.lateFail = errors.New("context deadline exceeded")
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if code(err) != "tailscale_api_error" || got.Status != StatusPending {
		t.Fatalf("want a failed approve: %v %+v", err, got)
	}
	if len(h.ts.attrs) != 0 {
		t.Errorf("attribute left on the device: %v (calls %v)", h.ts.attrs, h.ts.calls)
	}
	// And a closed browser tab does not abort the grant.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := h.svc.Approve(cctx, bob, r.ID, ""); err != nil || got.Status != StatusApproved {
		t.Errorf("cancelled caller context aborted the grant: %v %+v", err, got)
	}
}

// A lowered maximum shortens the grant, and the timeline says so.
func TestShortenedGrantIsNoted(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "s", Attribute: "s", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}, MaxDuration: Duration(4 * time.Hour)})
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(3 * time.Hour), Reason: "x"})
	upd := *w
	upd.MaxDuration, upd.DefaultDuration = Duration(time.Hour), Duration(time.Hour)
	h.svc.UpdateWorkflow(w.ID, upd)
	got, _ := h.svc.Approve(ctx, bob, r.ID, "")
	if last := got.Timeline[len(got.Timeline)-1].Note; !strings.Contains(last, "shortened from 3 hours to the flow's maximum of 1 hour") {
		t.Errorf("timeline: %q", last)
	}
}

func TestReviewFixes(t *testing.T) {
	member := []Principal{"autogroup:member"}

	// Votes from removed approvers don't show up in the count.
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "f", Attribute: "f", Requesters: member, Approvers: []Principal{"bob@example.com", "carol@example.com"}, ApprovalsRequired: 2})
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, bob, r.ID, "")
	upd := *w
	upd.Approvers = []Principal{"carol@example.com", "dave@example.com"}
	h.svc.UpdateWorkflow(w.ID, upd)
	if got, _ := h.svc.GetRequest(ctx, alice, r.ID); got.ApprovalsCounted != 0 || len(got.Approvals) != 1 {
		t.Errorf("counted %d of %d votes, want 0 of 1", got.ApprovalsCounted, len(got.Approvals))
	}

	// A request whose flow is gone stays hidden from strangers: 404, not 409.
	h = newHarness(t)
	w = h.workflow(t, rdpFlow(false))
	r, _ = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Cancel(ctx, alice, r.ID, "")
	if err := h.svc.DeleteWorkflow(w.ID); err != nil {
		t.Fatal(err)
	}
	stranger := Identity{Login: "eve@example.com", DeviceID: "nEVE"}
	if _, err := h.svc.Approve(ctx, stranger, r.ID, ""); AsError(err).Status != 404 {
		t.Errorf("stranger acting on a request with a deleted flow: %v, want 404", err)
	}

	// Lengths are characters, not bytes.
	h = newHarness(t)
	w = h.workflow(t, rdpFlow(false))
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: strings.Repeat("é", 1500)}); err != nil {
		t.Errorf("1500 accented characters refused: %v", err)
	}

	// Alice@ and alice@ are one approver, so a quorum of 2 needs someone else.
	h = newHarness(t)
	if _, err := h.svc.CreateWorkflow(Workflow{Name: "c", Attribute: "c", Requesters: member, Approvers: []Principal{"alice@example.com", "Alice@example.com"}, ApprovalsRequired: 2, MaxDuration: Duration(time.Hour)}); err == nil {
		t.Error("two spellings of one login counted as two approvers")
	}
}

func TestControlCharactersRefused(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "f", Attribute: "f", Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"bob@example.com"}})
	for _, reason := range []string{"look \x1b]52;c;aGk=\x07 here", "bell\x07", "c1 \u009b31m"} {
		if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: reason}); err == nil {
			t.Errorf("reason %q was accepted", reason)
		}
	}
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "line one\r\nline two\twith a tab"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Reason != "line one\nline two\twith a tab" {
		t.Errorf("reason = %q", r.Reason)
	}
	if _, err := h.svc.Decline(ctx, bob, r.ID, "no \x1b[2J"); err == nil {
		t.Error("a note with an escape sequence was accepted")
	}
}
