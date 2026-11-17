package jit

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

const (
	gAdmin = "00gADMIN000000000001"
	gRead  = "00gREAD0000000000002"
	gApp   = "00gAPP00000000000003"
	uAlice = "00uALICE"
	uCarol = "00uCAROL"
)

func oktaHarness(t *testing.T) (*harness, *okta.Fake) {
	t.Helper()
	h := newHarness(t)
	f := okta.NewFake()
	f.AddUser(uAlice, "alice@example.com")
	f.AddUser(uCarol, "carol@example.com")
	f.AddGroup(gAdmin, "AWS-Prod-Admin", "")
	f.AddGroup(gRead, "AWS-Prod-ReadOnly", "")
	f.AddGroup(gApp, "AD-Synced", "APP_GROUP")
	h.svc.Okta = f
	return h, f
}

func oktaFlow(groups ...OktaGroup) Workflow {
	return Workflow{
		Name: "AWS admin", OktaGroups: groups,
		Requesters: []Principal{"autogroup:member", "tag:agent"}, Approvers: []Principal{"bob@example.com"},
		MaxDuration: Duration(4 * time.Hour),
	}
}

func TestOktaFlowValidation(t *testing.T) {
	h, _ := oktaHarness(t)
	// Nothing to grant.
	if _, err := h.svc.CreateWorkflow(oktaFlow()); code(err) != "bad_request" || !strings.Contains(err.Error(), "must grant something") {
		t.Errorf("empty flow: %v", err)
	}
	// Names are looked up, IDs filled in; a name and an ID for one group collapse.
	w, err := h.svc.CreateWorkflow(oktaFlow(OktaGroup{Name: "AWS-Prod-Admin"}, OktaGroup{Name: gAdmin}))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.OktaGroups) != 1 || w.OktaGroups[0] != (OktaGroup{ID: gAdmin, Name: "AWS-Prod-Admin"}) || w.Attribute != "" {
		t.Errorf("flow = %+v", w)
	}
	if _, err := h.svc.CreateWorkflow(oktaFlow(OktaGroup{Name: "nope"})); code(err) != "bad_request" {
		t.Errorf("unknown group: %v", err)
	}
	if _, err := h.svc.CreateWorkflow(oktaFlow(OktaGroup{Name: "AD-Synced"})); code(err) != "bad_request" || !strings.Contains(err.Error(), "APP_GROUP") {
		t.Errorf("app group: %v", err)
	}
	// Two Okta-only flows are fine: they share no posture attribute.
	w2 := oktaFlow(OktaGroup{ID: gRead})
	w2.Name = "AWS read"
	if _, err := h.svc.CreateWorkflow(w2); err != nil {
		t.Errorf("second okta-only flow: %v", err)
	}
	// Without Okta configured, flows with groups are refused.
	h.svc.Okta = nil
	if _, err := h.svc.CreateWorkflow(oktaFlow(OktaGroup{ID: gRead})); code(err) != "conflict" {
		t.Errorf("unconfigured: %v", err)
	}
}

// A group given by ID and by name has to be one group. The ID is what is
// looked up, so the name of another group beside it would be dropped and
// the flow would grant a group its author did not name.
func TestGroupIDAndNameMustAgree(t *testing.T) {
	h, f := oktaHarness(t)
	_, err := h.svc.CreateWorkflow(oktaFlow(OktaGroup{ID: gRead, Name: "AWS-Prod-Admin"}))
	if code(err) != "bad_request" || !strings.Contains(err.Error(), gRead) ||
		!strings.Contains(err.Error(), `"AWS-Prod-ReadOnly"`) || !strings.Contains(err.Error(), `"AWS-Prod-Admin"`) {
		t.Fatalf("an ID and another group's name: %v, want a 400 that names both", err)
	}
	// The pair as jitd answers it is fine, and so is either half.
	w, err := h.svc.CreateWorkflow(oktaFlow(OktaGroup{ID: gRead, Name: "AWS-Prod-ReadOnly"}))
	if err != nil {
		t.Fatal(err)
	}

	// The group is renamed in Okta. The flow as it was read still saves,
	// and takes the new name; any other name for that ID is still refused.
	f.AddGroup(gRead, "AWS-Prod-Viewers", "")
	again := *w
	got, err := h.svc.UpdateWorkflow(w.ID, again)
	if err != nil {
		t.Fatalf("saving a flow as it was read, after a rename: %v", err)
	}
	if len(got.OktaGroups) != 1 || got.OktaGroups[0] != (OktaGroup{ID: gRead, Name: "AWS-Prod-Viewers"}) {
		t.Errorf("groups = %+v, want the new name", got.OktaGroups)
	}
	wrong := *got
	wrong.OktaGroups = []OktaGroup{{ID: gRead, Name: "AWS-Prod-Admin"}}
	if _, err := h.svc.UpdateWorkflow(w.ID, wrong); code(err) != "bad_request" {
		t.Errorf("updating with an ID and another group's name: %v, want 400", err)
	}
	if kept, _ := h.svc.GetWorkflow(w.ID); len(kept.OktaGroups) != 1 || kept.OktaGroups[0].ID != gRead {
		t.Errorf("the refused update changed the flow: %+v", kept.OktaGroups)
	}
}

func TestOktaApproveExpire(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{Name: "AWS-Prod-Admin"}, OktaGroup{Name: "AWS-Prod-ReadOnly"}))
	f.SetMember(gRead, uAlice) // alice already has read-only, outside jitd

	if _, err := h.svc.Submit(ctx, agent, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
		t.Errorf("tagged requester: %v", err)
	}
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "incident"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.OktaGroups) != 2 {
		t.Errorf("request did not snapshot the groups: %+v", r.OktaGroups)
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if m := f.Mutations(); fmt.Sprint(m) != fmt.Sprint([]string{"ADD " + gAdmin + " " + uAlice}) {
		t.Errorf("okta calls = %v", m)
	}
	if len(h.ts.calls) != 0 {
		t.Errorf("okta-only flow called Tailscale: %v", h.ts.calls)
	}
	if got.Status != StatusApproved || got.Okta == nil || got.Okta.UserID != uAlice ||
		fmt.Sprint(got.Okta.Added) != fmt.Sprint([]string{gAdmin}) || fmt.Sprint(got.Okta.Preexisting) != fmt.Sprint([]string{gRead}) {
		t.Errorf("approved = %+v okta=%+v", got, got.Okta)
	}
	if got.Enforcement.ConfirmedAt == nil || !got.Granted() {
		t.Errorf("okta-only grant not confirmed: %+v", got.Enforcement)
	}

	h.now = t0.Add(time.Hour)
	if n := h.svc.ExpireDue(); n != 1 {
		t.Fatalf("expired %d", n)
	}
	if m := f.Mutations(); fmt.Sprint(m) != fmt.Sprint([]string{"REMOVE " + gAdmin + " " + uAlice}) {
		t.Errorf("expiry okta calls = %v", m)
	}
	if f.Member(gAdmin, uAlice) || !f.Member(gRead, uAlice) {
		t.Errorf("memberships after expiry: admin=%v read=%v", f.Member(gAdmin, uAlice), f.Member(gRead, uAlice))
	}
	g, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if g.Okta.RemovedAt == nil || g.Enforcement.RemovedAt == nil {
		t.Errorf("removal not recorded: %+v %+v", g.Okta, g.Enforcement)
	}
	// Nothing more to do on later ticks.
	h.svc.ExpireDue()
	if m := f.Mutations(); len(m) != 0 {
		t.Errorf("later tick called Okta: %v", m)
	}
}

func TestOktaSharedMembership(t *testing.T) {
	h, f := oktaHarness(t)
	w1 := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	w2f := oktaFlow(OktaGroup{ID: gAdmin}, OktaGroup{ID: gRead})
	w2f.Name = "AWS admin + read"
	w2 := h.workflow(t, w2f)

	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w1.ID, Duration: Duration(30 * time.Minute), Reason: "a"})
	b, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w2.ID, Duration: Duration(2 * time.Hour), Reason: "b"})
	if _, err := h.svc.Approve(ctx, bob, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	gb, err := h.svc.Approve(ctx, bob, b.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	// The second request shares the admin membership the first added: it is
	// not "preexisting", or it would never come off.
	if len(gb.Okta.Preexisting) != 0 || len(gb.Okta.Added) != 2 {
		t.Errorf("second grant = %+v", gb.Okta)
	}
	f.Mutations()

	// The first ends: admin stays, held by the second.
	h.now = t0.Add(30 * time.Minute)
	h.svc.ExpireDue()
	if m := f.Mutations(); len(m) != 0 || !f.Member(gAdmin, uAlice) {
		t.Errorf("first expiry removed a shared membership: %v", m)
	}
	// Revoking the second removes both.
	if _, err := h.svc.Revoke(ctx, alice, b.ID, ""); err != nil {
		t.Fatal(err)
	}
	if f.Member(gAdmin, uAlice) || f.Member(gRead, uAlice) {
		t.Errorf("revoke left memberships: %v", f.Mutations())
	}
}

func TestOktaGrantFailureRollsBack(t *testing.T) {
	h, f := oktaHarness(t)
	fl := oktaFlow(OktaGroup{ID: gAdmin}, OktaGroup{ID: gRead})
	fl.Attribute = "aws"
	w := h.workflow(t, fl)
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	f.Fail["add:"+gRead] = errors.New("E0000006 forbidden")
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if code(err) != "tailscale_api_error" || got.Status != StatusPending || got.Okta != nil || len(got.Attributes) != 0 {
		t.Fatalf("approve = %v %+v", err, got)
	}
	if f.Member(gAdmin, uAlice) {
		t.Error("first group was not taken back")
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_aws"]; ok {
		t.Error("posture attribute was not taken back")
	}
	// Fixed: the approver can retry.
	delete(f.Fail, "add:"+gRead)
	if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || got.Status != StatusApproved {
		t.Fatalf("retry = %v %+v", err, got)
	}
	if !f.Member(gAdmin, uAlice) || !f.Member(gRead, uAlice) {
		t.Error("retry did not grant")
	}
	if _, ok := h.ts.attrs["nALICE|custom:jit_aws"]; !ok {
		t.Error("retry did not set the attribute")
	}
}

func TestOktaUnknownUser(t *testing.T) {
	h, _ := oktaHarness(t)
	fl := oktaFlow(OktaGroup{ID: gAdmin})
	fl.AllowSelfApproval = true
	w := h.workflow(t, fl)
	r, err := h.svc.Submit(ctx, bob, NewRequest{WorkflowID: w.ID, Reason: "x"}) // bob has no Okta user
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if code(err) != "tailscale_api_error" || got.Status != StatusPending || !strings.Contains(got.LastError, "Okta user") {
		t.Errorf("approve = %v %+v", err, got)
	}
}

func TestOktaRemovalRetried(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, bob, r.ID, "")
	f.Fail["remove:"+gAdmin] = errors.New("rate limited")
	got, err := h.svc.Revoke(ctx, bob, r.ID, "done")
	if err != nil || got.Status != StatusRevoked || got.Okta.RemovedAt != nil || !strings.Contains(got.Okta.Error, "rate limited") {
		t.Fatalf("revoke = %v %+v %+v", err, got, got.Okta)
	}
	h.svc.ExpireDue()
	if !f.Member(gAdmin, uAlice) {
		t.Fatal("membership removed while Okta fails")
	}
	delete(f.Fail, "remove:"+gAdmin)
	h.now = t0.Add(time.Minute)
	h.svc.ExpireDue()
	g, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if f.Member(gAdmin, uAlice) || g.Okta.RemovedAt == nil || g.Okta.Error != "" {
		t.Errorf("retry did not remove: member=%v okta=%+v", f.Member(gAdmin, uAlice), g.Okta)
	}
}

// A request ends but its removal from Okta fails, so the user is still in
// the group. A new approval for the same group must take the membership
// over, not record it as one the user had before: otherwise the retried
// removal cuts the new grant short.
func TestOktaRegrantWhileRemovalPending(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, bob, a.ID, "")
	f.Fail["remove:"+gAdmin] = errors.New("rate limited")
	if got, err := h.svc.Revoke(ctx, bob, a.ID, ""); err != nil || got.Okta.RemovedAt != nil {
		t.Fatalf("revoke = %v %+v", err, got.Okta)
	}

	b, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "again"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.Approve(ctx, bob, b.ID, "")
	if err != nil || !slices.Equal(got.Okta.Added, []string{gAdmin}) || len(got.Okta.Preexisting) != 0 {
		t.Fatalf("second approve = %v %+v", err, got.Okta)
	}

	// Okta recovers: the first request's removal is retried and must leave
	// the membership the second request now holds.
	delete(f.Fail, "remove:"+gAdmin)
	h.now = t0.Add(time.Minute)
	h.svc.ExpireDue()
	ga, _ := h.svc.GetRequest(ctx, alice, a.ID)
	if !f.Member(gAdmin, uAlice) || ga.Okta.RemovedAt == nil {
		t.Fatalf("after retry: member=%v first=%+v", f.Member(gAdmin, uAlice), ga.Okta)
	}

	// It comes off when the second request ends.
	if _, err := h.svc.Revoke(ctx, bob, b.ID, ""); err != nil {
		t.Fatal(err)
	}
	if f.Member(gAdmin, uAlice) {
		t.Error("membership left behind after the second request ended")
	}
}

// The same, in the window between a request's expiry time and the tick
// that marks it expired.
func TestOktaRegrantBeforeExpiryTick(t *testing.T) {
	h, f := oktaHarness(t)
	w1 := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	second := oktaFlow(OktaGroup{ID: gAdmin})
	second.Name = "AWS admin, break glass"
	w2 := h.workflow(t, second)
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w1.ID, Reason: "x", Duration: Duration(time.Hour)})
	h.svc.Approve(ctx, bob, a.ID, "")

	h.now = t0.Add(time.Hour + time.Second) // past the expiry, before the tick
	b, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w2.ID, Reason: "y", Duration: Duration(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.Approve(ctx, bob, b.ID, "")
	if err != nil || !slices.Equal(got.Okta.Added, []string{gAdmin}) {
		t.Fatalf("second approve = %v %+v", err, got.Okta)
	}
	h.svc.ExpireDue()
	if !f.Member(gAdmin, uAlice) {
		t.Fatal("the first request's expiry removed the membership the second holds")
	}
	h.now = t0.Add(3 * time.Hour)
	h.svc.ExpireDue()
	if f.Member(gAdmin, uAlice) {
		t.Error("membership left behind after both expired")
	}
}

// A membership the user had before jitd is still kept.
func TestOktaPreexistingKeptWithEndedRequests(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.Approve(ctx, bob, a.ID, "")
	h.svc.Revoke(ctx, bob, a.ID, "") // removed cleanly
	f.AddMember(ctx, gAdmin, uAlice) // then added by hand in Okta
	b, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "again"})
	got, err := h.svc.Approve(ctx, bob, b.ID, "")
	if err != nil || len(got.Okta.Added) != 0 || !slices.Equal(got.Okta.Preexisting, []string{gAdmin}) {
		t.Fatalf("approve = %v %+v", err, got.Okta)
	}
	h.svc.Revoke(ctx, bob, b.ID, "")
	if !f.Member(gAdmin, uAlice) {
		t.Error("a membership from outside jitd was removed")
	}
}

// Okta can be slow or down. None of the calls that add or remove a
// membership, or that look a group up for a flow, may run while the service
// lock is held: that would stall every other request.
func TestOktaCallsOutsideServiceLock(t *testing.T) {
	h, f := oktaHarness(t)
	var held []string
	f.Hook = func(call string) {
		if !h.svc.mu.TryLock() {
			held = append(held, call)
			return
		}
		h.svc.mu.Unlock()
	}
	fl := oktaFlow(OktaGroup{Name: "AWS-Prod-Admin"}, OktaGroup{ID: gRead})
	fl.Attribute = "aws"
	w := h.workflow(t, fl)
	if _, err := h.svc.UpdateWorkflow(w.ID, fl); err != nil {
		t.Fatal(err)
	}
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if got, err := h.svc.Approve(ctx, bob, a.ID, ""); err != nil || got.Status != StatusApproved {
		t.Fatalf("approve = %v %+v", err, got)
	}
	if got, err := h.svc.Revoke(ctx, bob, a.ID, ""); err != nil || got.Okta.RemovedAt == nil {
		t.Fatalf("revoke = %v %+v", err, got)
	}
	b, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "y", Duration: Duration(time.Hour)})
	h.svc.Approve(ctx, bob, b.ID, "")
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	if f.Member(gAdmin, uAlice) || f.Member(gRead, uAlice) {
		t.Fatal("expiry did not remove the memberships")
	}
	// A failed grant takes back what it added, also outside the lock.
	c, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "z"})
	f.Fail["add:"+gRead] = errors.New("boom")
	h.svc.Approve(ctx, bob, c.ID, "")
	if len(held) > 0 {
		t.Errorf("Okta calls made with the service lock held: %v", held)
	}
	if calls := f.Mutations(); len(calls) < 9 {
		t.Errorf("the test did not exercise the Okta calls: %v", calls)
	}
}

// While Okta is being called for an approval the service is not locked, so
// the request can change underneath it. The approval then does not go
// through and the memberships it added are taken back.
func TestOktaApproveLosesToCancel(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	f.Hook = func(call string) {
		if call == "add" {
			f.Hook = nil
			if _, err := h.svc.Cancel(ctx, alice, r.ID, "never mind"); err != nil {
				t.Errorf("cancel during the Okta call: %v", err)
			}
		}
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if code(err) != "conflict" {
		t.Fatalf("approve = %v %+v", err, got)
	}
	cur, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if cur.Status != StatusCancelled || cur.Okta != nil {
		t.Errorf("request = %s %+v", cur.Status, cur.Okta)
	}
	if f.Member(gAdmin, uAlice) {
		t.Error("the membership added for a cancelled request was left in Okta")
	}
}

// The posture attribute is set after the Okta memberships. If that fails,
// the memberships are taken back and the approver can retry.
func TestOktaTakenBackWhenAttributeFails(t *testing.T) {
	h, f := oktaHarness(t)
	fl := oktaFlow(OktaGroup{ID: gAdmin})
	fl.Attribute = "aws"
	w := h.workflow(t, fl)
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	f.SetMember(gRead, uAlice) // unrelated, must survive
	h.ts.fail["custom:jit_aws"] = errors.New("tailscale down")
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if code(err) != "tailscale_api_error" || got.Status != StatusPending || got.Okta != nil {
		t.Fatalf("approve = %v %+v", err, got)
	}
	if f.Member(gAdmin, uAlice) || !f.Member(gRead, uAlice) {
		t.Errorf("after the failure: admin=%v read=%v", f.Member(gAdmin, uAlice), f.Member(gRead, uAlice))
	}
	delete(h.ts.fail, "custom:jit_aws")
	if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || got.Status != StatusApproved || !f.Member(gAdmin, uAlice) {
		t.Fatalf("retry = %v %+v", err, got)
	}
}

// Two approvers click at once: one grant, one membership, no race.
func TestOktaConcurrentApprovals(t *testing.T) {
	h, f := oktaHarness(t)
	fl := oktaFlow(OktaGroup{ID: gAdmin})
	fl.Approvers = []Principal{"bob@example.com", "group:sre"}
	w := h.workflow(t, fl)
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	errs := make(chan error, 2)
	for _, who := range []Identity{bob, carol} {
		go func() {
			_, err := h.svc.Approve(ctx, who, r.ID, "")
			errs <- err
		}()
	}
	var failed int
	for range 2 {
		if err := <-errs; err != nil {
			failed++
			if code(err) != "conflict" {
				t.Errorf("losing approval = %v", err)
			}
		}
	}
	got, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if failed != 1 || got.Status != StatusApproved || len(got.Approvals) != 1 || !f.Member(gAdmin, uAlice) {
		t.Errorf("failed=%d request=%+v member=%v", failed, got, f.Member(gAdmin, uAlice))
	}
	if calls := f.Mutations(); len(calls) != 1 {
		t.Errorf("Okta changes = %v, want one add", calls)
	}
}

func TestOktaFlowChangeMakesPendingStale(t *testing.T) {
	h, _ := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gRead}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	w2 := *w
	w2.OktaGroups = []OktaGroup{{ID: gAdmin}}
	if _, err := h.svc.UpdateWorkflow(w.ID, w2); err != nil {
		t.Fatal(err)
	}
	g, _ := h.svc.GetRequest(ctx, alice, r.ID)
	if g.Status != StatusExpired || !strings.Contains(g.Timeline[len(g.Timeline)-1].Note, "AWS-Prod-Admin") {
		t.Errorf("pending request after the flow changed: %s %+v", g.Status, g.Timeline)
	}
}

func TestOktaOnlyFlowsSkipPolicy(t *testing.T) {
	h, _ := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gRead}))
	h.workflow(t, rdpFlow(false))
	snip := h.svc.PolicySnippet("tag:jit")
	if strings.Contains(snip, w.Name) || !strings.Contains(snip, "RDP") {
		t.Errorf("snippet:\n%s", snip)
	}
	if u := h.svc.PolicyUse(ctx, w); !u.OK() || u.NoEffect() || len(u.Problems()) != 0 {
		t.Errorf("policy use = %+v", u)
	}
}

const (
	gEng   = "00gENG00000000000004"
	gLeads = "00gLEADS000000000005"
	uBob   = "00uBOB"
)

// oktaPrincipalHarness: alice is in Engineering, carol in Eng-Leads, bob
// has an Okta user in neither.
func oktaPrincipalHarness(t *testing.T) (*harness, *okta.Fake) {
	t.Helper()
	h, f := oktaHarness(t)
	f.AddUser(uBob, "bob@example.com")
	f.AddGroup(gEng, "Engineering", "APP_GROUP") // pushed from a directory: fine to read
	f.AddGroup(gLeads, "Eng-Leads", "")
	f.SetMember(gEng, uAlice)
	f.SetMember(gLeads, uCarol)
	return h, f
}

func oktaGated() Workflow {
	return Workflow{
		Name: "DB", Attribute: "db",
		Requesters: []Principal{"okta:Engineering"}, Approvers: []Principal{"okta:Eng-Leads"},
		MaxDuration: Duration(time.Hour),
	}
}

func TestOktaPrincipalSyntax(t *testing.T) {
	for _, p := range []Principal{"okta:Engineering", "okta:Pit Crew / On Call", "okta:" + gLeads} {
		if err := ValidatePrincipal(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		if p.IsLogin() || !p.IsOkta() {
			t.Errorf("%s: IsLogin=%v IsOkta=%v", p, p.IsLogin(), p.IsOkta())
		}
	}
	for _, p := range []Principal{"okta:", "okta: ", "okta:a,b"} {
		if ValidatePrincipal(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if Principal("okta:ops@example.com").IsLogin() {
		t.Error("okta: with an @ is not a login")
	}
}

func TestOktaPrincipalFlowSave(t *testing.T) {
	h, _ := oktaPrincipalHarness(t)
	w := oktaGated()
	w.Approvers = []Principal{"okta:Nope"}
	if _, err := h.svc.CreateWorkflow(w); code(err) != "bad_request" || !strings.Contains(err.Error(), "Nope") {
		t.Errorf("unknown group: %v", err)
	}
	if _, err := h.svc.CreateWorkflow(oktaGated()); err != nil {
		t.Errorf("valid flow: %v", err)
	}
	h.svc.Okta = nil
	if _, err := h.svc.CreateWorkflow(oktaGated()); code(err) != "conflict" {
		t.Errorf("unconfigured: %v", err)
	}
}

func TestOktaPrincipalGates(t *testing.T) {
	h, f := oktaPrincipalHarness(t)
	w := h.workflow(t, oktaGated())

	if _, err := h.svc.Submit(ctx, bob, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
		t.Errorf("bob (not in Engineering) submitted: %v", err)
	}
	if _, err := h.svc.Submit(ctx, agent, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
		t.Errorf("tagged device submitted: %v", err)
	}
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); code(err) != "forbidden" && code(err) != "not_found" {
		t.Errorf("bob (not a lead) approved: %v", err)
	}
	logins, err := h.svc.ApproverLogins(ctx, w)
	if err != nil || fmt.Sprint(logins) != "[carol@example.com]" {
		t.Errorf("approver logins = %v, %v", logins, err)
	}
	if got, err := h.svc.Approve(ctx, carol, r.ID, ""); err != nil || got.Status != StatusApproved {
		t.Fatalf("carol approve = %v %+v", err, got)
	}

	// Bob joins Engineering in Okta: jitd sees it once the cache expires.
	f.SetMember(gEng, uBob)
	if _, err := h.svc.Submit(ctx, bob, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
		t.Errorf("cache not used: %v", err)
	}
	h.now = h.now.Add(OktaCacheTTL + time.Second)
	if _, err := h.svc.Submit(ctx, bob, NewRequest{WorkflowID: w.ID, Reason: "x"}); err != nil {
		t.Errorf("bob after joining: %v", err)
	}
}

func TestOktaPrincipalFailsClosed(t *testing.T) {
	h, f := oktaPrincipalHarness(t)
	w := h.workflow(t, oktaGated())
	f.Fail["usergroups:"+uAlice] = errors.New("okta down")
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
		t.Errorf("submit while Okta fails: %v", err)
	}
	// A login listed alongside still works.
	w2 := *w
	w2.Requesters = append(w2.Requesters, "alice@example.com")
	h.svc.UpdateWorkflow(w.ID, w2)
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"}); err != nil {
		t.Errorf("login requester while Okta fails: %v", err)
	}
}

func TestOktaPrincipalQuorumAndAdmin(t *testing.T) {
	h, _ := oktaPrincipalHarness(t)
	// carol is the only lead: she cannot approve her own request, so the
	// flow has nobody to approve it for her.
	fl := oktaGated()
	fl.Requesters = []Principal{"autogroup:member"}
	w := h.workflow(t, fl)
	if _, err := h.svc.Submit(ctx, carol, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "conflict" {
		t.Errorf("unreachable quorum: %v", err)
	}
	h.svc.Admins = []Principal{"okta:Eng-Leads"}
	if !h.svc.IsAdmin(ctx, carol) || h.svc.IsAdmin(ctx, alice) {
		t.Error("okta: admins")
	}
}

func TestOktaPrincipalSnippet(t *testing.T) {
	h, _ := oktaPrincipalHarness(t)
	h.workflow(t, oktaGated())
	snip := h.svc.PolicySnippet("tag:jit")
	if strings.Contains(snip, "okta:") || !strings.Contains(snip, `"src": ["autogroup:member"]`) {
		t.Errorf("snippet:\n%s", snip)
	}
}

func TestGlobMatch(t *testing.T) {
	for _, tc := range []struct {
		pat, s string
		want   bool
	}{
		{"On-Call", "On-Call", true},
		{"On-Call", "On-Call-2", false},
		{"jit.*", "jit.db.admin", true},
		{"jit.*", "xjit.a", false},
		{"Team-*-Admins", "Team-Infra-Admins", true},
		{"*Crew*", "Pit Crew / On Call", true},
		{"*", "anything", true},
		{"ab*ba", "aba", false},
		{"a*b*c", "abxc", true},
	} {
		if got := globMatch(tc.pat, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v", tc.pat, tc.s, got)
		}
	}
	if !allowed(nil, "x", "y") || allowed([]string{"a"}, "", "") || !allowed([]string{gAdmin}, gAdmin, "whatever") {
		t.Error("allowed")
	}
	if l := ParseOktaAllowlist(map[string]string{EnvOktaGrantAllowlist: " jit.* , ,On-Call"}); fmt.Sprint(l.Grant) != "[jit.* On-Call]" || fmt.Sprint(l.Read) != "[*]" {
		t.Errorf("parse = %+v", l)
	}
	// A list that is not set allows every group; one that is set with
	// nothing in it allows none.
	if l := ParseOktaAllowlist(map[string]string{EnvOktaReadAllowlist: " , "}); fmt.Sprint(l.Grant) != "[*]" || !AllowsAll(l.Grant) ||
		l.Read == nil || len(l.Read) != 0 || AllowsAll(l.Read) || allowed(l.Read, gAdmin, "AWS-Prod-Admin") {
		t.Errorf("set but empty = %+v", l)
	}
	if l := ParseOktaAllowlist(map[string]string{EnvOktaGrantAllowlist: ""}); AllowsAll(l.Grant) || allowed(l.Grant, gAdmin, "x") || !AllowsAll(l.Read) {
		t.Errorf("empty value = %+v", l)
	}
	if l := NoOktaGroups(); allowed(l.Grant, gAdmin, "x") || allowed(l.Read, gAdmin, "x") {
		t.Errorf("NoOktaGroups allows a group")
	}
	if l := (OktaAllowlist{}); !allowed(l.Grant, gAdmin, "x") || !AllowsAll(l.Read) {
		t.Errorf("the zero allowlist (never set) must allow every group")
	}
	if AllowsAll([]string{"jit.*"}) {
		t.Error("AllowsAll(jit.*)")
	}
}

func TestOktaGrantAllowlist(t *testing.T) {
	h, f := oktaHarness(t)
	lim := OktaAllowlist{Grant: []string{"AWS-Prod-*"}}
	h.svc.OktaLimits = func() OktaAllowlist { return lim }

	f.AddGroup("00gOTHER00000000009", "Finance-Admins", "")
	if _, err := h.svc.CreateWorkflow(oktaFlow(OktaGroup{Name: "Finance-Admins"})); code(err) != "forbidden" || !strings.Contains(err.Error(), EnvOktaGrantAllowlist) {
		t.Errorf("save outside allowlist: %v", err)
	}
	w := h.workflow(t, oktaFlow(OktaGroup{Name: "AWS-Prod-Admin"}, OktaGroup{ID: gRead}))

	// Approved while allowed; then the list narrows.
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "a"})
	if _, err := h.svc.Approve(ctx, bob, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	lim = OktaAllowlist{Grant: []string{"AWS-Prod-ReadOnly"}}
	c, _ := h.svc.Submit(ctx, carol, NewRequest{WorkflowID: w.ID, Reason: "c"})
	f.Mutations()
	got, err := h.svc.Approve(ctx, bob, c.ID, "")
	if err == nil || got.Status != StatusPending || !strings.Contains(got.LastError, "allowlist") {
		t.Errorf("approve after narrowing = %v %+v", err, got)
	}
	if m := f.Mutations(); len(m) != 0 {
		t.Errorf("narrowed approval touched Okta: %v", m)
	}
	// Removal of what was already granted still works.
	if _, err := h.svc.Revoke(ctx, alice, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if f.Member(gAdmin, uAlice) || f.Member(gRead, uAlice) {
		t.Error("revoke blocked by the allowlist")
	}
}

func TestOktaReadAllowlist(t *testing.T) {
	h, _ := oktaPrincipalHarness(t)
	lim := OktaAllowlist{Read: []string{"Eng*"}}
	h.svc.OktaLimits = func() OktaAllowlist { return lim }

	fl := oktaGated()
	fl.Approvers = []Principal{"okta:AWS-Prod-Admin"}
	if _, err := h.svc.CreateWorkflow(fl); code(err) != "forbidden" || !strings.Contains(err.Error(), EnvOktaReadAllowlist) {
		t.Errorf("save outside allowlist: %v", err)
	}
	w := h.workflow(t, oktaGated()) // Engineering and Eng-Leads: allowed
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"}); err != nil {
		t.Fatalf("allowed group: %v", err)
	}
	// Narrowed: Engineering no longer matches anyone, and Eng-Leads members
	// are no longer listed as approvers.
	lim = OktaAllowlist{Read: []string{"Nothing"}}
	h.now = h.now.Add(OktaCacheTTL + time.Second)
	if h.svc.matches(ctx, w.Requesters, alice) {
		t.Error("group outside the read allowlist matched")
	}
	if logins, err := h.svc.ApproverLogins(ctx, w); len(logins) != 0 || err == nil {
		t.Errorf("approver logins = %v, %v", logins, err)
	}
}

// jitd writes down which memberships it is about to add before it adds the
// first one, and the note goes away in the save that records the grant.
func TestOktaIntentRecordedBeforeAdd(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}, OktaGroup{ID: gRead}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	f.SetMember(gRead, uAlice) // held outside jitd: not jitd's to record or undo
	var seen *OktaIntent
	f.Hook = func(call string) {
		if call == "add" && seen == nil {
			if cur := h.svc.Request(r.ID); cur.OktaAdding != nil {
				seen = cur.OktaAdding
			} else {
				seen = &OktaIntent{}
			}
		}
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.UserID != uAlice || !slices.Equal(seen.Groups, []string{gAdmin}) {
		t.Fatalf("on record at the first Okta change: %+v", seen)
	}
	if got.OktaAdding != nil || !slices.Equal(got.Okta.Added, []string{gAdmin}) || !slices.Equal(got.Okta.Preexisting, []string{gRead}) {
		t.Errorf("after approve: adding=%+v okta=%+v", got.OktaAdding, got.Okta)
	}
	if cur := h.svc.Request(r.ID); cur.OktaAdding != nil {
		t.Errorf("stored intent after approve: %+v", cur.OktaAdding)
	}
}

// jitd stops after it added the user in Okta and before the approval was
// saved. The membership is on record, so the next tick (the first thing a
// restarted jitd does) takes it back; the request is still pending and can
// be approved again.
func TestOktaUnfinishedApprovalTakenBack(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if out := h.svc.grantOkta(ctx, r); out.err != nil { // an approval that gets no further
		t.Fatal(out.err)
	}
	cur := h.svc.Request(r.ID)
	if !f.Member(gAdmin, uAlice) || cur.Status != StatusPending || cur.OktaAdding == nil || cur.Okta != nil {
		t.Fatalf("after the unfinished approval: member=%v %s adding=%+v okta=%+v", f.Member(gAdmin, uAlice), cur.Status, cur.OktaAdding, cur.Okta)
	}
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if f.Member(gAdmin, uAlice) || cur.OktaAdding != nil || cur.Status != StatusPending {
		t.Fatalf("after the tick: member=%v %s adding=%+v", f.Member(gAdmin, uAlice), cur.Status, cur.OktaAdding)
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil || !slices.Equal(got.Okta.Added, []string{gAdmin}) || !f.Member(gAdmin, uAlice) {
		t.Errorf("approve afterwards = %v %+v", err, got)
	}
}

// The request is approved again before the tick cleaned up. The membership
// the unfinished approval left is jitd's: it is recorded as added, not as
// one the user had before, so it comes off when the access ends.
func TestOktaReapprovalAfterUnfinished(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x", Duration: Duration(time.Hour)})
	if out := h.svc.grantOkta(ctx, r); out.err != nil {
		t.Fatal(out.err)
	}
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil || !slices.Equal(got.Okta.Added, []string{gAdmin}) || len(got.Okta.Preexisting) != 0 || got.OktaAdding != nil {
		t.Fatalf("approve = %v okta=%+v adding=%+v", err, got.Okta, got.OktaAdding)
	}
	if calls := f.Mutations(); !slices.Equal(calls, []string{"ADD " + gAdmin + " " + uAlice}) {
		t.Errorf("Okta changes = %v", calls)
	}
	h.svc.ExpireDue() // nothing unfinished is left to take back
	if !f.Member(gAdmin, uAlice) {
		t.Fatal("the tick removed a membership a running request holds")
	}
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	if f.Member(gAdmin, uAlice) {
		t.Error("the membership outlived the access")
	}
}

// The approval fails and so does taking the membership back. It stays on
// record, the admins can see it, and the tick retries. Meanwhile another
// request may take the membership over; then it is no longer removed.
func TestOktaFailedTakeBackRetried(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		t.Run(fmt.Sprintf("takeover=%v", takeover), func(t *testing.T) {
			h, f := oktaHarness(t)
			fl := oktaFlow(OktaGroup{ID: gAdmin})
			fl.Attribute = "aws"
			w := h.workflow(t, fl)
			r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
			h.ts.fail["custom:jit_aws"] = errors.New("tailscale down")
			f.Fail["remove:"+gAdmin] = errors.New("okta down")
			got, err := h.svc.Approve(ctx, bob, r.ID, "")
			if code(err) != "tailscale_api_error" || got.Status != StatusPending || got.Okta != nil {
				t.Fatalf("approve = %v %+v", err, got)
			}
			if got.OktaAdding == nil || !slices.Equal(got.OktaAdding.Groups, []string{gAdmin}) || !strings.Contains(got.OktaAdding.Error, "okta down") {
				t.Fatalf("left on record: %+v", got.OktaAdding)
			}
			if ps := h.svc.OktaProblems(); len(ps) != 1 || ps[0].RequestID != r.ID || !strings.Contains(ps[0].Text, "AWS-Prod-Admin") {
				t.Errorf("problems = %+v", ps)
			}
			if takeover {
				other := oktaFlow(OktaGroup{ID: gAdmin})
				other.Name = "AWS admin, Okta only"
				w2 := h.workflow(t, other)
				b, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w2.ID, Reason: "y"})
				got, err := h.svc.Approve(ctx, bob, b.ID, "")
				if err != nil || !slices.Equal(got.Okta.Added, []string{gAdmin}) || len(got.Okta.Preexisting) != 0 {
					t.Fatalf("approve of the other request = %v %+v", err, got.Okta)
				}
			}
			delete(f.Fail, "remove:"+gAdmin)
			h.svc.ExpireDue()
			if f.Member(gAdmin, uAlice) != takeover {
				t.Errorf("member after the retry = %v, want %v", f.Member(gAdmin, uAlice), takeover)
			}
			if cur := h.svc.Request(r.ID); cur.OktaAdding != nil {
				t.Errorf("still on record: %+v", cur.OktaAdding)
			}
			if ps := h.svc.OktaProblems(); len(ps) != 0 {
				t.Errorf("problems after the retry = %+v", ps)
			}
		})
	}
}

// A removal that keeps failing is retried quietly at first. After
// OktaAlertAfter the admins are told, once, and told again when it clears.
func TestOktaStuckRemovalAlerts(t *testing.T) {
	for _, attr := range []string{"", "aws"} {
		t.Run("attribute="+attr, func(t *testing.T) {
			h, f := oktaHarness(t)
			rec := &recorder{}
			h.svc.Notify = rec
			fl := oktaFlow(OktaGroup{ID: gAdmin})
			fl.Attribute = attr
			w := h.workflow(t, fl)
			r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
			h.svc.Approve(ctx, bob, r.ID, "")
			f.Fail["remove:"+gAdmin] = errors.New("403 forbidden")
			h.svc.Revoke(ctx, bob, r.ID, "")
			count := func(typ string) int {
				n := 0
				for _, e := range rec.list() {
					if strings.HasPrefix(e, r.ID+" "+typ+" ") {
						n++
					}
				}
				return n
			}

			h.now = t0.Add(time.Minute)
			h.svc.ExpireDue()
			cur := h.svc.Request(r.ID)
			if cur.Okta.FailingSince == nil || !cur.Okta.FailingSince.Equal(t0) || cur.OktaStuck() || count(EventOktaStuck) != 0 || len(h.svc.OktaProblems()) != 0 {
				t.Fatalf("after a minute: %+v, %d alerts, problems %+v", cur.Okta, count(EventOktaStuck), h.svc.OktaProblems())
			}
			h.now = t0.Add(6 * time.Minute)
			h.svc.ExpireDue()
			h.now = t0.Add(7 * time.Minute)
			h.svc.ExpireDue()
			cur = h.svc.Request(r.ID)
			if !cur.OktaStuck() || count(EventOktaStuck) != 1 {
				t.Fatalf("after six minutes: %+v, %d alerts", cur.Okta, count(EventOktaStuck))
			}
			if ps := h.svc.OktaProblems(); len(ps) != 1 || ps[0].RequestID != r.ID || !strings.Contains(ps[0].Text, "403 forbidden") {
				t.Errorf("problems = %+v", ps)
			}

			delete(f.Fail, "remove:"+gAdmin)
			h.now = t0.Add(8 * time.Minute)
			h.svc.ExpireDue()
			cur = h.svc.Request(r.ID)
			if f.Member(gAdmin, uAlice) || cur.Okta.RemovedAt == nil || cur.Okta.FailingSince != nil || cur.Okta.Error != "" || cur.OktaStuck() {
				t.Fatalf("after Okta recovered: member=%v %+v", f.Member(gAdmin, uAlice), cur.Okta)
			}
			if len(h.svc.OktaProblems()) != 0 {
				t.Errorf("problems after Okta recovered = %+v", h.svc.OktaProblems())
			}
			// Someone is told that it went through: for an Okta-only request
			// that is the end of its access, otherwise the all-clear.
			want := EventOktaCleared
			if attr == "" {
				want = EventRemoved
			}
			if count(want) != 1 {
				t.Errorf("%s events = %d; all: %v", want, count(want), rec.list())
			}
		})
	}
}

// Someone takes the user out of the group in Okta while the access is
// running. jitd notes it on the request and leaves Okta alone.
func TestOktaVerifyNotesMissing(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}, OktaGroup{ID: gRead}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x", Duration: Duration(2 * time.Hour)})
	h.svc.Approve(ctx, bob, r.ID, "")
	lookups := func() int {
		n := 0
		for _, c := range f.Calls {
			if c == "USERGROUPS "+uAlice {
				n++
			}
		}
		f.Mutations() // clears the log
		return n
	}
	lookups()
	h.svc.ExpireDue()
	cur := h.svc.Request(r.ID)
	if lookups() != 1 || cur.Okta.CheckedAt == nil || len(cur.Okta.Missing) != 0 {
		t.Fatalf("first comparison: %+v", cur.Okta)
	}
	f.RemoveMember(ctx, gAdmin, uAlice) // an Okta admin, not jitd
	h.now = t0.Add(time.Minute)
	h.svc.ExpireDue()
	if n := lookups(); n != 0 {
		t.Errorf("compared again after a minute (%d lookups)", n)
	}
	h.now = t0.Add(11 * time.Minute)
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if !slices.Equal(cur.Okta.Missing, []string{gAdmin}) || !slices.Equal(cur.OktaMissingLabels(), []string{"AWS-Prod-Admin"}) {
		t.Fatalf("missing = %v %v", cur.Okta.Missing, cur.OktaMissingLabels())
	}
	if f.Member(gAdmin, uAlice) || !f.Member(gRead, uAlice) {
		t.Errorf("jitd changed Okta: admin=%v read=%v", f.Member(gAdmin, uAlice), f.Member(gRead, uAlice))
	}
	if calls := f.Mutations(); len(calls) != 0 {
		t.Errorf("Okta changes = %v", calls)
	}
	// The end of the access is as usual.
	h.now = t0.Add(3 * time.Hour)
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if f.Member(gRead, uAlice) || cur.Okta.RemovedAt == nil || len(cur.OktaMissingLabels()) != 0 {
		t.Errorf("after expiry: read=%v %+v", f.Member(gRead, uAlice), cur.Okta)
	}
}

// Credentials that stop working show before a removal needs them.
func TestOktaCredentialsCheck(t *testing.T) {
	h, f := oktaHarness(t)
	h.svc.ExpireDue()
	if ps := h.svc.OktaProblems(); len(ps) != 0 {
		t.Fatalf("problems with working credentials = %+v", ps)
	}
	f.Fail["check"] = errors.New("401 invalid token")
	h.now = t0.Add(30 * time.Minute)
	h.svc.ExpireDue()
	if len(h.svc.OktaProblems()) != 0 {
		t.Error("checked again within the hour")
	}
	h.now = t0.Add(61 * time.Minute)
	h.svc.ExpireDue()
	if ps := h.svc.OktaProblems(); len(ps) != 1 || ps[0].RequestID != "" || !strings.Contains(ps[0].Text, "401 invalid token") {
		t.Fatalf("problems = %+v", ps)
	}
	delete(f.Fail, "check")
	h.now = t0.Add(63 * time.Minute)
	h.svc.ExpireDue()
	if len(h.svc.OktaProblems()) != 1 {
		t.Error("a failing check was repeated after two minutes")
	}
	h.now = t0.Add(67 * time.Minute)
	h.svc.ExpireDue()
	if ps := h.svc.OktaProblems(); len(ps) != 0 {
		t.Errorf("problems after the credentials were fixed = %+v", ps)
	}
}

// Two approvers answer at once. The second read the request while the
// first was halfway (its note of what it was adding was on record) and
// then loses. Taking the loser's attempt back must not remove what the
// winner's approval holds.
func TestOktaLosingApprovalLeavesWinnersGrant(t *testing.T) {
	h, f := oktaHarness(t)
	fl := oktaFlow(OktaGroup{ID: gAdmin})
	fl.Approvers = []Principal{"bob@example.com", "group:sre"}
	w := h.workflow(t, fl)
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	var stale *AccessRequest
	f.Hook = func(call string) {
		if call == "add" && stale == nil {
			stale = h.svc.Request(r.ID) // what the second approver saw
		}
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	f.Hook = nil
	if stale == nil || stale.Status != StatusPending || stale.OktaAdding == nil {
		t.Fatalf("the request halfway through the first approval: %+v", stale)
	}
	f.Mutations()
	out := h.svc.grantOkta(ctx, stale)
	if out.err == nil {
		t.Fatal("a grant for an approved request went through")
	}
	h.svc.takeBackOkta(ctx, r.ID, out)
	if calls := f.Mutations(); len(calls) != 0 || !f.Member(gAdmin, uAlice) {
		t.Errorf("Okta changes = %v, member=%v", calls, f.Member(gAdmin, uAlice))
	}
	if got, err := h.svc.Approve(ctx, carol, r.ID, ""); code(err) != "conflict" || !f.Member(gAdmin, uAlice) {
		t.Errorf("second approval = %v %+v, member=%v", err, got, f.Member(gAdmin, uAlice))
	}
}
