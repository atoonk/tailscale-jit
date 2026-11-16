package jit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// offOkta is an Okta client that can be switched off the way okta.Dynamic
// is when its credentials go away: Enabled turns false and every call fails.
type offOkta struct {
	*okta.Fake
	on *bool
}

func (o offOkta) Enabled() bool { return *o.on }
func (o offOkta) Err() error {
	if *o.on {
		return nil
	}
	return okta.ErrUnconfigured
}
func (o offOkta) RemoveMember(ctx context.Context, g, u string) error {
	if !*o.on {
		return okta.ErrUnconfigured
	}
	return o.Fake.RemoveMember(ctx, g, u)
}

func eventCount(rec *recorder, typ string) (n int) {
	for _, e := range rec.list() {
		if strings.Contains(e, " "+typ+" ") {
			n++
		}
	}
	return
}

// Okta losing its credentials while a grant is running must not hide the
// membership that is then left behind: the removal is tried, fails, and the
// admins are told, and it goes through once Okta is back.
func TestOktaOffWithMembershipsInPlace(t *testing.T) {
	h, f := oktaHarness(t)
	on := true
	h.svc.Okta = offOkta{f, &on}
	rec := &recorder{}
	h.svc.Notify = rec
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	on = false
	// Still running: the admins already hear that jitd cannot look after it.
	if ps := h.svc.OktaProblems(); len(ps) != 1 || !strings.Contains(ps[0].Text, "Okta is off") {
		t.Errorf("problems while the grant runs with Okta off = %+v", ps)
	}
	h.now = t0.Add(61 * time.Minute)
	h.svc.ExpireDue()
	cur := h.svc.Request(r.ID)
	if cur.Status != StatusExpired || !cur.OktaRemovalPending() || cur.Okta.Error == "" || cur.Okta.FailingSince == nil {
		t.Fatalf("after expiry with Okta off: status %s, okta %+v", cur.Status, cur.Okta)
	}
	h.now = t0.Add(70 * time.Minute)
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if !cur.OktaStuck() || eventCount(rec, EventOktaStuck) != 1 {
		t.Errorf("the admins were not alerted: stuck=%v, events %v", cur.OktaStuck(), rec.list())
	}
	ps := h.svc.OktaProblems()
	if len(ps) != 2 || !strings.Contains(ps[0].Text, "Okta is off") || ps[1].RequestID != r.ID {
		t.Errorf("problems = %+v", ps)
	}
	if !f.Member(gAdmin, uAlice) {
		t.Fatal("the fake removed the membership while Okta was off")
	}
	on = true
	h.now = t0.Add(71 * time.Minute)
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if f.Member(gAdmin, uAlice) || cur.Okta.RemovedAt == nil || len(h.svc.OktaProblems()) != 0 || eventCount(rec, EventRemoved) != 1 {
		t.Errorf("after Okta came back: member=%v okta=%+v problems=%+v events=%v", f.Member(gAdmin, uAlice), cur.Okta, h.svc.OktaProblems(), rec.list())
	}
}

// Okta that is off and was never used is not a problem.
func TestOktaOffAndUnusedIsQuiet(t *testing.T) {
	h, f := oktaHarness(t)
	on := false
	h.svc.Okta = offOkta{f, &on}
	h.svc.ExpireDue()
	if ps := h.svc.OktaProblems(); len(ps) != 0 {
		t.Errorf("problems = %+v", ps)
	}
	if len(f.Calls) != 0 {
		t.Errorf("calls to Okta while off: %v", f.Calls)
	}
}

// Twenty removals that keep failing must not keep a newer one from being
// tried: what was tried longest ago goes first.
func TestOktaStuckRemovalsDoNotStarveLaterOnes(t *testing.T) {
	h, f := oktaHarness(t)
	for i := 0; i < oktaBatch; i++ {
		gid := fmt.Sprintf("00gSTUCK%012d", i)
		f.AddGroup(gid, fmt.Sprintf("Stuck-%02d", i), "")
		fl := oktaFlow(OktaGroup{ID: gid})
		fl.Name = fmt.Sprintf("stuck %02d", i)
		w := h.workflow(t, fl)
		r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
			t.Fatal(err)
		}
		f.Fail["remove:"+gid] = errors.New("403 forbidden")
	}
	fl := oktaFlow(OktaGroup{ID: gRead})
	fl.Name = "AWS read"
	w2 := h.workflow(t, fl)
	h.now = t0.Add(30 * time.Minute)
	r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w2.ID, Duration: Duration(time.Hour), Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(65 * time.Minute) // the twenty expire, and fail
	h.svc.ExpireDue()
	h.now = t0.Add(2 * time.Hour) // the read request expires
	h.svc.ExpireDue()
	cur := h.svc.Request(r.ID)
	if f.Member(gRead, uAlice) || cur.Okta.RemovedAt == nil {
		t.Errorf("the newer removal was not tried on its first tick: member=%v okta=%+v", f.Member(gRead, uAlice), cur.Okta)
	}
}

// A second approval for a group another running request holds checks Okta
// too: if someone took the user out meanwhile, they are added again rather
// than recorded as having access they do not have.
func TestOktaSharedGroupIsChecked(t *testing.T) {
	h, f := oktaHarness(t)
	wa := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	fl := oktaFlow(OktaGroup{ID: gAdmin})
	fl.Name = "AWS admin two"
	wb := h.workflow(t, fl)
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: wa.ID, Duration: Duration(2 * time.Hour), Reason: "x"})
	if _, err := h.svc.Approve(ctx, bob, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	f.RemoveMember(ctx, gAdmin, uAlice) // an Okta admin, not jitd
	b, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: wb.ID, Duration: Duration(time.Hour), Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	rb, err := h.svc.Approve(ctx, bob, b.ID, "")
	if err != nil || rb.Status != StatusApproved || !f.Member(gAdmin, uAlice) || !slices.Contains(rb.Okta.Added, gAdmin) {
		t.Errorf("err=%v status=%s okta=%+v member=%v", err, statusOf(rb), rb.Okta, f.Member(gAdmin, uAlice))
	}
	// A failing membership check stops the approval before anything changes.
	c, err := h.svc.Submit(ctx, carol, NewRequest{WorkflowID: wa.ID, Duration: Duration(time.Hour), Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	f.Mutations() // forget what happened so far
	f.Fail["ismember:"+gAdmin] = errors.New("500 try later")
	if _, err := h.svc.Approve(ctx, bob, c.ID, ""); err == nil {
		t.Error("approved although the membership could not be checked")
	}
	if cur, ms := h.svc.Request(c.ID), f.Mutations(); cur.Status != StatusPending || cur.OktaAdding != nil || len(ms) != 0 {
		t.Errorf("after a failed check: status %s, adding %+v, mutations %v", cur.Status, cur.OktaAdding, ms)
	}
}

func statusOf(r *AccessRequest) Status {
	if r == nil {
		return ""
	}
	return r.Status
}

// okta:<name> means the one group with that name. A second group carrying
// the same name makes the reference ambiguous, and it then matches nobody.
func TestOktaPrincipalSameNameGroup(t *testing.T) {
	h, f := oktaPrincipalHarness(t)
	h.svc.Admins = []Principal{"okta:Eng-Leads"}
	if !h.svc.IsAdmin(ctx, carol) || h.svc.IsAdmin(ctx, alice) {
		t.Fatal("before the second group exists: carol should be an admin, alice not")
	}
	f.AddGroup("00gEVIL0000000000009", "Eng-Leads", "APP_GROUP")
	f.SetMember("00gEVIL0000000000009", uAlice)
	h.now = h.now.Add(2 * time.Minute) // past the cache
	if h.svc.IsAdmin(ctx, alice) {
		t.Error("alice is a jitd admin through a second group that merely shares the name")
	}
	if err := h.svc.CheckOktaPrincipal(ctx, "okta:Eng-Leads"); err == nil {
		t.Error("an ambiguous group name passes the start-up check")
	}
	// By ID there is no doubt.
	h.svc.Admins = []Principal{Principal("okta:" + gLeads)}
	if !h.svc.IsAdmin(ctx, carol) || h.svc.IsAdmin(ctx, alice) {
		t.Error("by ID: carol should be an admin, alice not")
	}
	// A group that is named like another group's ID confers nothing either.
	f.AddGroup("00gEVIL0000000000010", gLeads, "")
	f.SetMember("00gEVIL0000000000010", uAlice)
	h.now = h.now.Add(2 * time.Minute)
	if h.svc.IsAdmin(ctx, alice) {
		t.Error("alice is an admin through a group named like the admin group's ID")
	}
}

// A suspended Okta user keeps their groups in Okta, but is in none for jitd.
func TestOktaSuspendedUserMatchesNothing(t *testing.T) {
	h, f := oktaPrincipalHarness(t)
	h.svc.Admins = []Principal{"okta:Eng-Leads"}
	u := f.Users["carol@example.com"]
	u.Status = "SUSPENDED"
	f.Users["carol@example.com"] = u
	if h.svc.IsAdmin(ctx, carol) {
		t.Error("suspended carol is still a jitd admin through okta:Eng-Leads")
	}
}

// A lookup that fails after using its whole timeout is still remembered,
// and while Okta does not answer, other lookups fail at once.
func TestOktaLookupFailureIsCached(t *testing.T) {
	h, f := oktaPrincipalHarness(t)
	w := h.workflow(t, oktaGated())
	f.Fail["usergroups:"+uAlice] = fmt.Errorf("okta API: %w", context.DeadlineExceeded)
	f.Hook = func(call string) {
		if call == "usergroups" {
			h.now = h.now.Add(oktaLookupTimeout)
		}
	}
	if _, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"}); err == nil {
		t.Fatal("submitted although the group lookup failed")
	}
	calls := len(f.Calls)
	if calls == 0 {
		t.Fatal("no lookup at all")
	}
	h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	h.svc.IsAdmin(ctx, carol) // another person: Okta is known to be down
	h.svc.Admins = []Principal{"okta:Eng-Leads"}
	if h.svc.IsAdmin(ctx, carol) {
		t.Error("carol matched while Okta is known not to answer")
	}
	if len(f.Calls) != calls {
		t.Errorf("Okta was called again within the error window: %v", f.Calls[calls:])
	}
	// It is tried again afterwards.
	delete(f.Fail, "usergroups:"+uAlice)
	f.Hook = nil
	h.now = h.now.Add(oktaErrTTL)
	if !h.svc.IsAdmin(ctx, carol) {
		t.Error("carol does not match after the error window")
	}
}

// When Okta refuses an add, there is nothing to take back, so the next tick
// must not remove a membership somebody gives the user afterwards.
func TestOktaRefusedAddIsNotTakenBack(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	f.Fail["add:"+gAdmin] = &okta.APIError{Method: "PUT", Path: "/api/v1/groups/x/users/y", Status: 403, Summary: "forbidden"}
	f.Fail["remove:"+gAdmin] = errors.New("503")
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err == nil {
		t.Fatal("approved although Okta refused the add")
	}
	if cur := h.svc.Request(r.ID); cur.Status != StatusPending || cur.OktaAdding != nil {
		t.Fatalf("after a refused add: status %s, adding %+v", cur.Status, cur.OktaAdding)
	}
	f.SetMember(gAdmin, uAlice) // an Okta admin gives alice standing membership
	delete(f.Fail, "add:"+gAdmin)
	delete(f.Fail, "remove:"+gAdmin)
	h.now = t0.Add(time.Minute)
	h.svc.ExpireDue()
	if !f.Member(gAdmin, uAlice) {
		t.Error("jitd removed a membership it never added")
	}
}

// An add that fails without an answer may have been applied: it is taken back.
func TestOktaUnansweredAddIsTakenBack(t *testing.T) {
	h, f := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	f.Fail["add:"+gAdmin] = errors.New("connection reset")
	f.Fail["remove:"+gAdmin] = errors.New("connection reset")
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err == nil {
		t.Fatal("approved although the add failed")
	}
	cur := h.svc.Request(r.ID)
	if cur.OktaAdding == nil || !slices.Contains(cur.OktaAdding.Groups, gAdmin) {
		t.Fatalf("the intent was dropped although the add may have gone through: %+v", cur.OktaAdding)
	}
	f.SetMember(gAdmin, uAlice) // it did go through
	delete(f.Fail, "remove:"+gAdmin)
	h.now = t0.Add(time.Minute)
	h.svc.ExpireDue()
	if f.Member(gAdmin, uAlice) || h.svc.Request(r.ID).OktaAdding != nil {
		t.Error("the membership of an approval that did not finish was not taken back")
	}
}

// When a request ends while a newer request of the same user holds the same
// group, the user stays in it. The record must say so, not "removed".
func TestOktaKeptMembershipIsNotCalledRemoved(t *testing.T) {
	h, f := oktaHarness(t)
	rec := &recorder{}
	h.svc.Notify = rec
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	if _, err := h.svc.Approve(ctx, bob, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	f.Fail["remove:"+gAdmin] = errors.New("403 forbidden")
	h.svc.Revoke(ctx, bob, a.ID, "")
	h.now = t0.Add(6 * time.Minute)
	h.svc.ExpireDue()
	h.now = t0.Add(7 * time.Minute)
	h.svc.ExpireDue()
	if !h.svc.Request(a.ID).OktaStuck() {
		t.Fatal("not stuck")
	}
	b, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "again"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, bob, b.ID, ""); err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(8 * time.Minute)
	h.svc.ExpireDue()
	ga := h.svc.Request(a.ID)
	if !f.Member(gAdmin, uAlice) {
		t.Fatal("alice lost the membership the second request holds")
	}
	if ga.Okta.RemovedAt == nil || fmt.Sprint(ga.Okta.Kept) != "["+gAdmin+"]" ||
		len(ga.OktaRemovedLabels()) != 0 || fmt.Sprint(ga.OktaKeptLabels()) != "[AWS-Prod-Admin]" {
		t.Errorf("first request: okta=%+v removed=%v kept=%v", ga.Okta, ga.OktaRemovedLabels(), ga.OktaKeptLabels())
	}
	// The second request removes it when it ends.
	delete(f.Fail, "remove:"+gAdmin)
	h.now = t0.Add(2 * time.Hour)
	h.svc.ExpireDue()
	gb := h.svc.Request(b.ID)
	if f.Member(gAdmin, uAlice) || gb.Okta.RemovedAt == nil || len(gb.Okta.Kept) != 0 || fmt.Sprint(gb.OktaRemovedLabels()) != "[AWS-Prod-Admin]" {
		t.Errorf("second request: member=%v okta=%+v", f.Member(gAdmin, uAlice), gb.Okta)
	}
}

// ctxOkta is the fake, except that a removal fails on a dead context the
// way the real client does.
type ctxOkta struct{ *okta.Fake }

func (c ctxOkta) RemoveMember(ctx context.Context, g, u string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Fake.RemoveMember(ctx, g, u)
}

// A removal that had to wait for an approval in flight gets its time from
// when it has the lock: the wait must not turn into a recorded failure.
func TestOktaRemovalDeadlineStartsAfterTheLock(t *testing.T) {
	h, f := oktaHarness(t)
	h.svc.Okta = ctxOkta{f}
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x", Duration: Duration(time.Hour)})
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(2 * time.Hour)
	if n := h.svc.expireDue(); n != 1 {
		t.Fatalf("expired %d", n)
	}
	dead, cancel := context.WithCancel(context.Background())
	cancel() // the tick's time ran out while it waited
	h.svc.releaseOktaOne(dead, r.ID)
	if g := h.svc.Request(r.ID); f.Member(gAdmin, uAlice) || g.Okta.Error != "" || g.Okta.RemovedAt == nil {
		t.Errorf("after waiting for the lock: member = %v, okta = %+v", f.Member(gAdmin, uAlice), g.Okta)
	}
}
