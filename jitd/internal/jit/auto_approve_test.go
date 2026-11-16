package jit

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func autoFlow(groups ...OktaGroup) Workflow {
	w := oktaFlow(groups...)
	w.AutoApprove, w.Approvers = true, nil
	return w
}

func TestAutoApproveValidation(t *testing.T) {
	h, _ := oktaHarness(t)
	// Approvers are optional with auto-approval, required without.
	if _, err := h.svc.CreateWorkflow(autoFlow(OktaGroup{ID: gAdmin})); err != nil {
		t.Errorf("auto flow without approvers: %v", err)
	}
	manual := autoFlow(OktaGroup{ID: gRead})
	manual.Name, manual.AutoApprove = "manual", false
	if _, err := h.svc.CreateWorkflow(manual); code(err) != "bad_request" {
		t.Errorf("manual flow without approvers: %v", err)
	}
	// A quorum larger than the named approvers is fine when nobody votes.
	q := autoFlow(OktaGroup{ID: gRead})
	q.Name, q.Approvers, q.ApprovalsRequired = "quorum", []Principal{"bob@example.com"}, 3
	if _, err := h.svc.CreateWorkflow(q); err != nil {
		t.Errorf("auto flow with unreachable quorum: %v", err)
	}
}

func TestAutoApproveOkta(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{Name: "AWS-Prod-Admin"}))

	// Listed as requestable even though nobody can approve.
	rq := h.svc.Requestable(ctx, alice)
	if len(rq) != 1 || !rq[0].AutoApprove {
		t.Fatalf("requestable = %+v", rq)
	}
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusApproved || r.ExpiresAt == nil || !r.ExpiresAt.Equal(t0.Add(time.Hour)) || !f.Member(gAdmin, uAlice) {
		t.Fatalf("submitted = %+v, member = %v", r, f.Member(gAdmin, uAlice))
	}
	if len(r.Approvals) != 0 {
		t.Errorf("auto-approval recorded a vote: %+v", r.Approvals)
	}
	last := r.Timeline[len(r.Timeline)-1]
	if last.Type != "approved" || last.Actor != AutoActor {
		t.Errorf("timeline = %+v", r.Timeline)
	}
	// Still expires and is taken back like any other grant.
	h.now = t0.Add(time.Hour)
	if n := h.svc.ExpireDue(); n != 1 || f.Member(gAdmin, uAlice) {
		t.Errorf("expired %d, still member = %v", n, f.Member(gAdmin, uAlice))
	}
}

func TestAutoApproveRevoke(t *testing.T) {
	h, f := oktaHarness(t)
	fl := autoFlow(OktaGroup{ID: gAdmin})
	fl.Approvers = []Principal{"bob@example.com"}
	w := h.workflow(t, fl)
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	// A listed approver may revoke an automatic grant.
	if got, err := h.svc.Revoke(ctx, bob, r.ID, "not needed"); err != nil || got.Status != StatusRevoked || f.Member(gAdmin, uAlice) {
		t.Fatalf("revoke = %v %+v", err, got)
	}
}

func TestAutoApproveFailureCancels(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{ID: gAdmin}))
	f.Fail["add:"+gAdmin] = errors.New("E0000006 forbidden")
	_, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	e := AsError(err)
	if code(err) != "tailscale_api_error" || e.RequestID == "" {
		t.Fatalf("submit = %v (request %q)", err, e.RequestID)
	}
	g, _ := h.svc.GetRequest(ctx, alice, e.RequestID)
	if g.Status != StatusCancelled || f.Member(gAdmin, uAlice) {
		t.Fatalf("after failure: %+v", g)
	}
	// Fixed: submitting again works (the cancelled request does not block it).
	delete(f.Fail, "add:"+gAdmin)
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil || r.Status != StatusApproved {
		t.Fatalf("resubmit = %v %+v", err, r)
	}
}

func TestAutoApprovePosture(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, Workflow{
		Name: "ssh", Attribute: "ssh", AutoApprove: true,
		Requesters: []Principal{"autogroup:member"}, MaxDuration: Duration(time.Hour),
	})
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil || r.Status != StatusApproved {
		t.Fatalf("submit = %v %+v", err, r)
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_ssh"]; !ok {
		t.Errorf("attribute not set: %v", fmt.Sprint(h.ts.attrs))
	}
}

// An automatic approval makes its Okta calls the way Approve does: without
// the service lock, and a failed grant takes back what it added.
func TestAutoApproveOktaOutsideServiceLock(t *testing.T) {
	h, f := oktaHarness(t)
	var held []string
	f.Hook = func(call string) {
		if !h.svc.mu.TryLock() {
			held = append(held, call)
			return
		}
		h.svc.mu.Unlock()
	}
	fl := autoFlow(OktaGroup{ID: gAdmin}, OktaGroup{ID: gRead})
	fl.Attribute = "aws"
	w := h.workflow(t, fl)
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil || r.Status != StatusApproved || !f.Member(gAdmin, uAlice) || !f.Member(gRead, uAlice) {
		t.Fatalf("submit = %v %+v", err, r)
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_aws"]; !ok {
		t.Error("attribute not set")
	}
	if _, err := h.svc.Revoke(ctx, alice, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	// The second group fails: the first is taken back, the attribute is
	// never set, and the request is cancelled.
	f.Fail["add:"+gRead] = errors.New("boom")
	_, err = h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "y"})
	e := AsError(err)
	if code(err) != "tailscale_api_error" || e.RequestID == "" {
		t.Fatalf("submit = %v", err)
	}
	if g := h.svc.Request(e.RequestID); g.Status != StatusCancelled || g.Okta != nil || f.Member(gAdmin, uAlice) {
		t.Errorf("after a failed grant: %+v, still member = %v", g, f.Member(gAdmin, uAlice))
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_aws"]; ok {
		t.Error("attribute left on the device after a failed grant")
	}
	if len(held) > 0 {
		t.Errorf("Okta calls made with the service lock held: %v", held)
	}
}

// A flow that stops approving on its own between submit and grant leaves
// the request cancelled, not granted.
func TestAutoApproveFlowChangedMeanwhile(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{ID: gAdmin}))
	f.Hook = func(call string) {
		if call != "add" {
			return
		}
		f.Hook = nil
		manual := *w
		manual.AutoApprove, manual.Approvers = false, []Principal{"bob@example.com"}
		if _, err := h.svc.UpdateWorkflow(w.ID, manual); err != nil {
			t.Error(err)
		}
	}
	_, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	e := AsError(err)
	if code(err) != "conflict" || e.RequestID == "" {
		t.Fatalf("submit = %v", err)
	}
	if g := h.svc.Request(e.RequestID); g.Status != StatusCancelled || f.Member(gAdmin, uAlice) {
		t.Errorf("request = %+v, member = %v", g, f.Member(gAdmin, uAlice))
	}
}

// A failed automatic grant whose memberships cannot be taken back leaves a
// note on the cancelled request, and the next tick takes them back.
func TestAutoApproveFailedTakeBackIsRetried(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{ID: gAdmin}, OktaGroup{ID: gRead}))
	f.Fail["add:"+gRead] = errors.New("boom")
	f.Fail["remove:"+gAdmin] = errors.New("okta is down")
	_, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	e := AsError(err)
	if e.RequestID == "" {
		t.Fatalf("submit = %v", err)
	}
	g := h.svc.Request(e.RequestID)
	if g.Status != StatusCancelled || g.OktaAdding == nil || !f.Member(gAdmin, uAlice) {
		t.Fatalf("after the failed grant: status %s, intent %+v, member = %v", g.Status, g.OktaAdding, f.Member(gAdmin, uAlice))
	}
	delete(f.Fail, "remove:"+gAdmin)
	h.svc.ExpireDue()
	if g := h.svc.Request(e.RequestID); g.OktaAdding != nil || f.Member(gAdmin, uAlice) {
		t.Errorf("after the tick: intent %+v, member = %v", g.OktaAdding, f.Member(gAdmin, uAlice))
	}
}

// An automatic flow must not hand out a group whose members decide: one
// request would make anyone an approver or a jitd admin, with nobody saying
// yes. Refused when either side of the pair is saved.
func TestAutoApproveCannotHandOutARole(t *testing.T) {
	h, _ := oktaHarness(t)
	named := func(w Workflow, name string) Workflow { w.Name = name; return w }
	refused := func(what string, err error) {
		t.Helper()
		if code(err) != "conflict" || !strings.Contains(err.Error(), "with nobody deciding") {
			t.Errorf("%s: %v", what, err)
		}
	}

	// The admins, by Okta group name.
	h.svc.Admins = []Principal{"okta:AWS-Prod-Admin"}
	_, err := h.svc.CreateWorkflow(named(autoFlow(OktaGroup{ID: gAdmin}), "admin group"))
	refused("automatic flow granting the admins' group", err)
	// With approvers deciding, the same flow is the admin's call.
	manual, err := h.svc.CreateWorkflow(named(oktaFlow(OktaGroup{ID: gAdmin}), "admin group, approved"))
	if err != nil {
		t.Fatalf("the same flow with approvers: %v", err)
	}
	auto := *manual
	auto.AutoApprove = true
	_, err = h.svc.UpdateWorkflow(manual.ID, auto)
	refused("making that flow automatic", err)

	// The approvers of another flow, by group ID.
	gated := named(oktaFlow(OktaGroup{ID: gAdmin}), "gated")
	gated.Approvers = []Principal{"okta:" + gRead}
	if _, err := h.svc.CreateWorkflow(gated); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.CreateWorkflow(named(autoFlow(OktaGroup{ID: gRead}), "read group"))
	refused("automatic flow granting another flow's approver group", err)

	// The other way round: the automatic flow is there first.
	h.svc.Admins = nil
	if _, err := h.svc.CreateWorkflow(named(autoFlow(OktaGroup{ID: gAdmin}), "self-serve")); err != nil {
		t.Fatalf("automatic flow for a group nobody decides with: %v", err)
	}
	late := named(oktaFlow(OktaGroup{ID: gRead}), "late")
	late.Approvers = []Principal{"okta:AWS-Prod-Admin"}
	_, err = h.svc.CreateWorkflow(late)
	refused("approvers from a group an automatic flow hands out", err)
}

// "Decide in the browser only" exists for flows where a Slack identity is
// not enough. On an automatic flow the request is the decision.
func TestAutoApproveBrowserOnlyFromSlack(t *testing.T) {
	h := newHarness(t)
	w := h.workflow(t, Workflow{Name: "ssh", Attribute: "ssh", AutoApprove: true,
		Requesters: []Principal{"autogroup:member"}, MaxDuration: Duration(time.Hour),
		Slack: &WorkflowSlack{Channel: "C0SREONCALL", BrowserOnly: true}})
	viaSlack := alice
	viaSlack.Via, viaSlack.SlackUser = ViaSlack, "T0FAKE/UALICE"
	if r, err := h.svc.Submit(ctx, viaSlack, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
		t.Errorf("from Slack on a browser-only automatic flow: %v, %s", err, statusOf(r))
	}
	if r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"}); err != nil || r.Status != StatusApproved {
		t.Errorf("from the browser: %v", err)
	}
}

// Making a flow automatic approves every request that follows, so who did
// it is kept with the flow and named on each grant.
func TestAutoApproveRecordsWhoMadeItAutomatic(t *testing.T) {
	h := newHarness(t)
	fl := Workflow{Name: "ssh", Attribute: "ssh", AutoApprove: true, UpdatedBy: "leo@example.com",
		Requesters: []Principal{"autogroup:member"}, MaxDuration: Duration(time.Hour)}
	fl.AutoApproveBy = "someone@else.example" // not the caller's to set
	w := h.workflow(t, fl)
	if w.AutoApproveBy != "leo@example.com" || w.AutoApproveAt == nil {
		t.Fatalf("made automatic by %q at %v", w.AutoApproveBy, w.AutoApproveAt)
	}
	// Another admin's edit that leaves it automatic keeps the record.
	edit := *w
	edit.UpdatedBy, edit.Description = "sam@example.com", "edited"
	w2, err := h.svc.UpdateWorkflow(w.ID, edit)
	if err != nil || w2.AutoApproveBy != "leo@example.com" || w2.UpdatedBy != "sam@example.com" {
		t.Fatalf("after an edit: %v, by %q, saved by %q", err, w2.AutoApproveBy, w2.UpdatedBy)
	}
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil || !r.AutoApproved() {
		t.Fatalf("submit: %v", err)
	}
	if ev := r.Timeline[len(r.Timeline)-1]; ev.Type != "approved" || !strings.Contains(ev.Note, "leo@example.com made automatic") {
		t.Errorf("grant recorded as %q: %q", ev.Type, ev.Note)
	}
	// Manual again, then automatic again: the record is the new one.
	edit.AutoApprove, edit.Approvers = false, []Principal{"bob@example.com"}
	if w3, err := h.svc.UpdateWorkflow(w.ID, edit); err != nil || w3.AutoApproveBy != "" || w3.AutoApproveAt != nil {
		t.Fatalf("manual again: %v, %+v", err, w3)
	}
	edit.AutoApprove = true
	if w4, err := h.svc.UpdateWorkflow(w.ID, edit); err != nil || w4.AutoApproveBy != "sam@example.com" {
		t.Fatalf("automatic again: %v, %+v", err, w4)
	}
}

// Turning a flow automatic expires the requests that were waiting for
// people: they are not granted by a flow edit.
func TestAutoApproveFlipExpiresPending(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	nw := *w
	nw.AutoApprove, nw.Approvers = true, nil
	if _, err := h.svc.UpdateWorkflow(w.ID, nw); err != nil {
		t.Fatal(err)
	}
	cur := h.svc.Request(r.ID)
	if cur.Status != StatusExpired || f.Member(gAdmin, uAlice) {
		t.Errorf("status %s, member %v", cur.Status, f.Member(gAdmin, uAlice))
	}
	if n := cur.Timeline[len(cur.Timeline)-1].Note; !strings.Contains(n, "automatically") {
		t.Errorf("note = %q", n)
	}
}

// A request on an automatic flow that a stopped jitd left pending is ended
// on the next tick: nobody may be able to approve it, and it would block
// the requester from filing again.
func TestAutoApproveUnfinishedIsEnded(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, autoFlow(OktaGroup{ID: gAdmin}))
	// One that is being granted right now is left alone.
	r, auto, err := h.svc.submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil || !auto {
		t.Fatalf("submit = %v auto=%v", err, auto)
	}
	h.svc.ExpireDue()
	if cur := h.svc.Request(r.ID); cur.Status != StatusPending {
		t.Fatalf("a grant in flight was ended by the tick: %s", cur.Status)
	}
	// jitd stops there and starts again.
	h.svc.autoBusy = nil
	h.svc.ExpireDue()
	if cur := h.svc.Request(r.ID); cur.Status != StatusExpired {
		t.Errorf("an automatic request nobody can approve is still %s after the tick", cur.Status)
	}
	got, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "again"})
	if err != nil || got.Status != StatusApproved || !f.Member(gAdmin, uAlice) {
		t.Errorf("submitting again = %v, %s", err, statusOf(got))
	}
	if len(h.svc.autoBusy) != 0 {
		t.Errorf("autoBusy not cleared: %v", h.svc.autoBusy)
	}
}
