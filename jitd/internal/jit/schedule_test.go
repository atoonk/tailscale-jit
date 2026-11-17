package jit

import (
	"errors"
	"testing"
	"time"
)

func at(d time.Duration) *time.Time { t := t0.Add(d); return &t }

// schedFlow is the RDP flow with room for the longer windows these tests use.
func schedFlow() Workflow {
	w := rdpFlow(false)
	w.MaxDuration = Duration(4 * time.Hour)
	return w
}

func TestScheduledGrantPosture(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, schedFlow())

	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(2 * time.Hour), Reason: "maintenance", StartAt: at(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusPending || r.StartAt == nil || !r.StartAt.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("submitted = %+v", r)
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusScheduled || got.ExpiresAt == nil || !got.ExpiresAt.Equal(t0.Add(26*time.Hour)) {
		t.Fatalf("approved = %+v", got)
	}
	if len(h.ts.calls) != 0 || len(got.Attributes) != 0 {
		t.Fatalf("granted before the start: calls %v, attributes %v", h.ts.calls, got.Attributes)
	}

	// Ticks before the start do nothing.
	h.now = t0.Add(23 * time.Hour)
	h.svc.ExpireDue()
	if g, _ := h.svc.GetRequest(ctx, alice, r.ID); g.Status != StatusScheduled || len(h.ts.calls) != 0 {
		t.Fatalf("before start: %s, calls %v", g.Status, h.ts.calls)
	}

	// At the start, the tick grants it until the window's end.
	h.now = t0.Add(24*time.Hour + 10*time.Second)
	h.svc.ExpireDue()
	g, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if g.Status != StatusApproved || !g.ExpiresAt.Equal(t0.Add(26*time.Hour)) {
		t.Fatalf("after start: %+v", g)
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_windows_rdp"]; !ok {
		t.Fatalf("attribute not set at the start: %v", h.ts.attrs)
	}
	if last := g.Timeline[len(g.Timeline)-1]; last.Type != "started" {
		t.Errorf("timeline = %+v", g.Timeline)
	}

	// And it ends like any other grant.
	h.now = t0.Add(26 * time.Hour)
	if n := h.svc.ExpireDue(); n != 1 {
		t.Errorf("expired %d", n)
	}
}

func TestScheduledGrantOktaRetriesThenStarts(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{ID: gAdmin}))
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x", StartAt: at(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusScheduled || f.Member(gAdmin, uAlice) {
		t.Fatalf("auto-approved schedule = %s, member %v", r.Status, f.Member(gAdmin, uAlice))
	}
	// The first attempt fails: it stays scheduled and says why, once.
	f.Fail["add:"+gAdmin] = errors.New("E0000006 forbidden")
	h.now = t0.Add(time.Hour)
	h.svc.ExpireDue()
	h.now = t0.Add(time.Hour + 30*time.Second)
	h.svc.ExpireDue()
	g, _ := h.svc.GetRequest(ctx, alice, r.ID)
	fails := 0
	for _, e := range g.Timeline {
		if e.Type == "start_failed" {
			fails++
		}
	}
	if g.Status != StatusScheduled || g.LastError == "" || fails != 1 || f.Member(gAdmin, uAlice) {
		t.Fatalf("after failures: %s %q, %d start_failed entries", g.Status, g.LastError, fails)
	}
	// Fixed: the next tick starts it.
	delete(f.Fail, "add:"+gAdmin)
	h.now = t0.Add(time.Hour + time.Minute)
	h.svc.ExpireDue()
	g, _ = h.svc.GetRequest(ctx, alice, r.ID)
	if g.Status != StatusApproved || !f.Member(gAdmin, uAlice) || g.LastError != "" {
		t.Fatalf("after fix: %s, member %v, err %q", g.Status, f.Member(gAdmin, uAlice), g.LastError)
	}
	// It ends at the window's end, not an hour after it started.
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	if f.Member(gAdmin, uAlice) {
		t.Error("membership outlived the window")
	}
}

func TestScheduledGrantWindowPassesWithoutStarting(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x", StartAt: at(time.Hour)})
	f.Fail["add:"+gAdmin] = errors.New("down")
	h.now = t0.Add(time.Hour)
	h.svc.ExpireDue()
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	if g, _ := h.svc.GetRequest(ctx, alice, r.ID); g.Status != StatusExpired {
		t.Fatalf("status = %s", g.Status)
	}
}

func TestScheduledGrantRevokedBeforeStart(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, schedFlow())
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x", StartAt: at(time.Hour)})
	h.svc.Approve(ctx, bob, r.ID, "")
	if a := h.svc.Permissions(ctx, alice, mustGet(t, h, r.ID)); !a.Revoke {
		t.Error("the requester cannot call off their scheduled request")
	}
	got, err := h.svc.Revoke(ctx, alice, r.ID, "not needed")
	if err != nil || got.Status != StatusRevoked {
		t.Fatalf("revoke = %v %+v", err, got)
	}
	h.now = t0.Add(time.Hour)
	h.svc.ExpireDue()
	if len(h.ts.calls) != 0 {
		t.Errorf("revoked schedule still granted: %v", h.ts.calls)
	}
}

func TestScheduledGrantCalledOffWhenFlowChanges(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, schedFlow())
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x", StartAt: at(time.Hour)})
	h.svc.Approve(ctx, bob, r.ID, "")
	changed := *w
	changed.Disabled = true
	if _, err := h.svc.UpdateWorkflow(w.ID, changed); err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(time.Hour)
	h.svc.ExpireDue()
	g := mustGet(t, h, r.ID)
	if g.Status != StatusRevoked || len(h.ts.calls) != 0 {
		t.Fatalf("status %s, calls %v", g.Status, h.ts.calls)
	}
}

func TestScheduledGrantLateApproval(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, schedFlow())
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(2 * time.Hour), Reason: "x", StartAt: at(time.Hour)})
	// Approved half an hour into the window: access starts now and still
	// ends with the window.
	h.now = t0.Add(90 * time.Minute)
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil || got.Status != StatusApproved || !got.ExpiresAt.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("late approval = %v %+v", err, got)
	}
}

func TestScheduledGrantPendingExpiresWithWindow(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, schedFlow())
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x", StartAt: at(time.Hour)})
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	if g := mustGet(t, h, r.ID); g.Status != StatusExpired {
		t.Fatalf("status = %s", g.Status)
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err == nil {
		t.Error("approved after the window")
	}
}

func TestScheduledGrantValidationAndOverlap(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, schedFlow())
	sub := func(start *time.Time, dur time.Duration) (*AccessRequest, error) {
		return h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(dur), Reason: "x", StartAt: start})
	}
	if _, err := sub(at(31*24*time.Hour), time.Hour); code(err) != "bad_request" {
		t.Errorf("too far ahead: %v", err)
	}
	if _, err := sub(at(-time.Hour), time.Hour); code(err) != "bad_request" {
		t.Errorf("in the past: %v", err)
	}
	// Within a minute of now means now.
	now, err := sub(at(30*time.Second), time.Hour)
	if err != nil || now.StartAt != nil {
		t.Fatalf("near-now start: %v %+v", err, now)
	}
	// A request for tomorrow coexists with today's; one overlapping it does not.
	if _, err := sub(at(24*time.Hour), time.Hour); err != nil {
		t.Errorf("non-overlapping schedule refused: %v", err)
	}
	if _, err := sub(at(24*time.Hour+30*time.Minute), time.Hour); code(err) != "conflict" {
		t.Errorf("overlapping schedule: %v", err)
	}
	if _, err := sub(nil, time.Hour); code(err) != "conflict" {
		t.Errorf("overlapping the pending one: %v", err)
	}
	// The flow cannot be deleted with a scheduled request outstanding.
	if err := h.svc.DeleteWorkflow(w.ID); err == nil {
		t.Error("deleted a flow with live requests")
	}
}

func mustGet(t *testing.T, h *harness, id string) *AccessRequest {
	t.Helper()
	r, err := h.svc.GetRequest(ctx, alice, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A request scheduled days ahead is not cut off by the flow's approval
// timeout (24h by default): it stays open until its window ends.
func TestScheduledGrantOutlivesApprovalTimeout(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, schedFlow())
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x", StartAt: at(72 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Two days on, well past the approval timeout, it is still pending.
	h.now = t0.Add(48 * time.Hour)
	h.svc.ExpireDue()
	if g := mustGet(t, h, r.ID); g.Status != StatusPending {
		t.Fatalf("after the approval timeout: %s", g.Status)
	}
	// And can still be approved.
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil || got.Status != StatusScheduled {
		t.Fatalf("approve = %v %+v", err, got)
	}

	// A request that starts on approval still times out as before.
	h.now = t0
	now, err := h.svc.Submit(ctx, carol, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "y"})
	if err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(25 * time.Hour)
	h.svc.ExpireDue()
	if g, _ := h.svc.GetRequest(ctx, carol, now.ID); g.Status != StatusExpired {
		t.Errorf("immediate request after the approval timeout: %s", g.Status)
	}
}
