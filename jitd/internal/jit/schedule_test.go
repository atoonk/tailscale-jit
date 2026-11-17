package jit

import (
	"errors"
	"slices"
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

// schedOktaFlow grants an Okta group and a posture attribute, with bob
// approving.
func schedOktaFlow() Workflow {
	w := oktaFlow(OktaGroup{ID: gAdmin})
	w.Attribute = "aws"
	return w
}

// scheduled files a request an hour ahead on flow w and has bob approve it.
func scheduled(t *testing.T, h *harness, w *Workflow) *AccessRequest {
	t.Helper()
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x", StartAt: at(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil || got.Status != StatusScheduled {
		t.Fatalf("approve = %v, %s", err, statusOf(got))
	}
	return got
}

// A scheduled start adds the Okta memberships the way an approval does:
// what it is about to add is on record before the first change in Okta, and
// no Okta call is made with the service lock held.
func TestScheduledStartOktaLikeAnApproval(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, schedOktaFlow())
	r := scheduled(t, h, w)
	if n := len(f.Mutations()); n != 0 || f.Member(gAdmin, uAlice) {
		t.Fatalf("approving ahead of time changed Okta: %v", f.Mutations())
	}
	var held []string
	var seen *OktaIntent
	f.Hook = func(call string) {
		if !h.svc.mu.TryLock() {
			held = append(held, call)
		} else {
			h.svc.mu.Unlock()
		}
		if call == "add" && seen == nil {
			seen = &OktaIntent{}
			if cur := h.svc.Request(r.ID); cur.OktaAdding != nil {
				seen = cur.OktaAdding
			}
		}
	}
	h.now = t0.Add(time.Hour)
	h.svc.ExpireDue()
	f.Hook = nil
	if len(held) > 0 {
		t.Errorf("Okta calls made with the service lock held: %v", held)
	}
	if seen == nil || seen.UserID != uAlice || !slices.Equal(seen.Groups, []string{gAdmin}) {
		t.Fatalf("on record at the first Okta change: %+v", seen)
	}
	cur := h.svc.Request(r.ID)
	if cur.Status != StatusApproved || cur.OktaAdding != nil || cur.Okta == nil || !slices.Equal(cur.Okta.Added, []string{gAdmin}) || !f.Member(gAdmin, uAlice) {
		t.Fatalf("after the start: %s adding=%+v okta=%+v member=%v", cur.Status, cur.OktaAdding, cur.Okta, f.Member(gAdmin, uAlice))
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_aws"]; !ok {
		t.Errorf("attribute not set at the start: %v", h.ts.attrs)
	}
	// And both come off at the end of the window.
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	if cur := h.svc.Request(r.ID); cur.Status != StatusExpired || f.Member(gAdmin, uAlice) {
		t.Errorf("after the window: %s member=%v", cur.Status, f.Member(gAdmin, uAlice))
	}
}

// The posture attribute is set after the Okta memberships. If that fails at
// a scheduled start, the memberships are taken back, the request stays
// scheduled, and the next tick tries again.
func TestScheduledStartTakesOktaBackWhenAttributeFails(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, schedOktaFlow())
	r := scheduled(t, h, w)
	h.ts.fail["custom:jit_aws"] = errors.New("tailscale down")
	h.now = t0.Add(time.Hour)
	h.svc.ExpireDue()
	cur := h.svc.Request(r.ID)
	if cur.Status != StatusScheduled || cur.LastError == "" || cur.Okta != nil || cur.OktaAdding != nil || f.Member(gAdmin, uAlice) {
		t.Fatalf("after the failed start: %s err=%q okta=%+v adding=%+v member=%v", cur.Status, cur.LastError, cur.Okta, cur.OktaAdding, f.Member(gAdmin, uAlice))
	}
	delete(h.ts.fail, "custom:jit_aws")
	h.now = t0.Add(time.Hour + time.Minute)
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if cur.Status != StatusApproved || !f.Member(gAdmin, uAlice) || cur.LastError != "" {
		t.Fatalf("after the retry: %s member=%v err=%q", cur.Status, f.Member(gAdmin, uAlice), cur.LastError)
	}
}

// While Okta is being called for a start the service is not locked, so the
// request can be revoked underneath it. It then does not start, and the
// membership added for it is taken back.
func TestScheduledStartLosesToRevoke(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, schedOktaFlow())
	r := scheduled(t, h, w)
	f.Hook = func(call string) {
		if call == "add" {
			f.Hook = nil
			if _, err := h.svc.Revoke(ctx, bob, r.ID, "not today"); err != nil {
				t.Errorf("revoke during the Okta call: %v", err)
			}
		}
	}
	h.now = t0.Add(time.Hour)
	h.svc.ExpireDue()
	cur := h.svc.Request(r.ID)
	if cur.Status != StatusRevoked || cur.Okta != nil || cur.OktaAdding != nil {
		t.Errorf("request = %s okta=%+v adding=%+v", cur.Status, cur.Okta, cur.OktaAdding)
	}
	if f.Member(gAdmin, uAlice) {
		t.Error("the membership added for a revoked request was left in Okta")
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_aws"]; ok {
		t.Errorf("attribute set for a revoked request: %v", h.ts.attrs)
	}
}

// jitd stops after it added the user in Okta for a start and before the
// start was saved. The membership is on record, so the next tick's start
// takes it over as jitd's own: it comes off when the window ends.
func TestScheduledStartAfterUnfinishedStart(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, schedOktaFlow())
	r := scheduled(t, h, w)
	h.now = t0.Add(time.Hour)
	if out := h.svc.grantOkta(ctx, h.svc.Request(r.ID)); out.err != nil { // a start that gets no further
		t.Fatal(out.err)
	}
	cur := h.svc.Request(r.ID)
	if !f.Member(gAdmin, uAlice) || cur.Status != StatusScheduled || cur.OktaAdding == nil {
		t.Fatalf("after the unfinished start: member=%v %s adding=%+v", f.Member(gAdmin, uAlice), cur.Status, cur.OktaAdding)
	}
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if cur.Status != StatusApproved || cur.OktaAdding != nil || cur.Okta == nil || !slices.Equal(cur.Okta.Added, []string{gAdmin}) || len(cur.Okta.Preexisting) != 0 {
		t.Fatalf("after the tick: %s adding=%+v okta=%+v", cur.Status, cur.OktaAdding, cur.Okta)
	}
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	if f.Member(gAdmin, uAlice) {
		t.Error("membership outlived the window")
	}
}

// The same, but the request is revoked before jitd is back: nothing starts
// it, so the tick takes the membership back.
func TestScheduledUnfinishedStartTakenBackAfterRevoke(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, schedOktaFlow())
	r := scheduled(t, h, w)
	h.now = t0.Add(time.Hour)
	if out := h.svc.grantOkta(ctx, h.svc.Request(r.ID)); out.err != nil {
		t.Fatal(out.err)
	}
	if _, err := h.svc.Revoke(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	h.svc.ExpireDue()
	cur := h.svc.Request(r.ID)
	if f.Member(gAdmin, uAlice) || cur.Status != StatusRevoked || cur.OktaAdding != nil {
		t.Errorf("after the tick: member=%v %s adding=%+v", f.Member(gAdmin, uAlice), cur.Status, cur.OktaAdding)
	}
}

// A scheduled request on an automatic flow that a stopped jitd left pending
// is ended on the next tick, like any other: nobody may be able to approve
// it.
func TestScheduledAutoApproveUnfinishedIsEnded(t *testing.T) {
	h, _ := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{ID: gAdmin}))
	r, auto, err := h.svc.submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x", StartAt: at(time.Hour)})
	if err != nil || !auto {
		t.Fatalf("submit = %v auto=%v", err, auto)
	}
	h.svc.ExpireDue()
	if cur := h.svc.Request(r.ID); cur.Status != StatusPending {
		t.Fatalf("a grant in flight was ended by the tick: %s", cur.Status)
	}
	h.svc.autoBusy = nil // jitd stops there and starts again
	h.svc.ExpireDue()
	if cur := h.svc.Request(r.ID); cur.Status != StatusExpired {
		t.Errorf("an automatic request nobody can approve is still %s after the tick", cur.Status)
	}
}
