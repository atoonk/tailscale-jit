package jit

import (
	"errors"
	"fmt"
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
