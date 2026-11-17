package jit

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// What jitd does with a group provider is the same for each of them: these
// tests run once per provider, through its fake. The Okta tests in
// okta_test.go go deeper; the ones here are what a new provider must also
// get right.

const (
	ggAdmin = "01ggadmin"
	ggRead  = "02ggread"
	ggDyn   = "03ggdyn"
	gaAdmin = "aws-admin@example.com"
	gaRead  = "aws-read@example.com"
	mAlice  = "alice@example.com" // alice, as Google knows her
)

func addGoogle(h *harness) *google.Fake {
	f := google.NewFake()
	f.AddGroup(ggAdmin, gaAdmin, false)
	f.AddGroup(ggRead, gaRead, false)
	f.AddGroup(ggDyn, "all-eng@example.com", true)
	h.svc.Google = f
	h.svc.GoogleLimits = func() GoogleLimits { return GoogleLimits{Domains: []string{"example.com"}} }
	return f
}

func googleHarness(t *testing.T) (*harness, *google.Fake) {
	t.Helper()
	h := newHarness(t)
	return h, addGoogle(h)
}

func googleFlow(groups ...GroupRef) Workflow {
	w := oktaFlow()
	w.Name, w.GoogleGroups = "Cloud admin", groups
	return w
}

// groupRig is one provider with alice and two groups jitd can manage.
type groupRig struct {
	h      *harness
	kind   *groupKind
	g1, g2 string // group IDs
	n1     string // what people call g1
	member string // alice's ID with the provider
	in     func(group string) bool
	put    func(group string) // alice joins, outside jitd
	take   func(group string) // alice is taken out, outside jitd
	fail   map[string]error   // "add:<group>", "remove:<group>"
	muts   func() []string
}

func (g *groupRig) provider() *groupProvider {
	for _, p := range g.h.svc.providers() {
		if p.groupKind == g.kind {
			return p
		}
	}
	panic("no provider")
}

func (g *groupRig) flow(name, attr string, ids ...string) Workflow {
	w := oktaFlow()
	w.Name, w.Attribute = name, attr
	for _, id := range ids {
		*g.kind.flowGroups(&w) = append(*g.kind.flowGroups(&w), GroupRef{ID: id})
	}
	return w
}

func (g *groupRig) grant(r *AccessRequest) *GroupGrant { return g.kind.granted(r) }

func eachProvider(t *testing.T, run func(t *testing.T, g *groupRig)) {
	t.Run("okta", func(t *testing.T) {
		h, f := oktaHarness(t)
		run(t, &groupRig{
			h: h, kind: oktaKind, g1: gAdmin, g2: gRead, n1: "AWS-Prod-Admin", member: uAlice,
			in:   func(g string) bool { return f.Member(g, uAlice) },
			put:  func(g string) { f.SetMember(g, uAlice) },
			take: func(g string) { f.RemoveMember(ctx, g, uAlice); f.Mutations() },
			fail: f.Fail, muts: f.Mutations,
		})
	})
	t.Run("google", func(t *testing.T) {
		h, f := googleHarness(t)
		run(t, &groupRig{
			h: h, kind: googleKind, g1: ggAdmin, g2: ggRead, n1: gaAdmin, member: mAlice,
			in:   func(g string) bool { return f.Member(g, mAlice) },
			put:  func(g string) { f.SetMember(g, mAlice) },
			take: func(g string) { f.RemoveMember(ctx, g, mAlice); f.Mutations() },
			fail: f.Fail, muts: f.Mutations,
		})
	})
}

func TestGroupsApproveAndExpire(t *testing.T) {
	eachProvider(t, func(t *testing.T, g *groupRig) {
		h := g.h
		w := h.workflow(t, g.flow("admin", "", g.g1, g.g2))
		g.put(g.g2) // alice already has this one, outside jitd
		if _, err := h.svc.Submit(ctx, agent, NewRequest{WorkflowID: w.ID, Reason: "x"}); code(err) != "forbidden" {
			t.Errorf("tagged requester: %v", err)
		}
		r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "incident"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.svc.Approve(ctx, bob, r.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		if m := g.muts(); !slices.Equal(m, []string{"ADD " + g.g1 + " " + g.member}) {
			t.Errorf("changes = %v", m)
		}
		gr := g.grant(got)
		if got.Status != StatusApproved || gr == nil || gr.UserID != g.member || !slices.Equal(gr.Added, []string{g.g1}) || !slices.Equal(gr.Preexisting, []string{g.g2}) {
			t.Fatalf("approved = %+v grant=%+v", got, gr)
		}
		if got.Enforcement.ConfirmedAt == nil || !got.Granted() || len(h.ts.calls) != 0 {
			t.Errorf("a groups-only grant: enforcement %+v, Tailscale calls %v", got.Enforcement, h.ts.calls)
		}
		h.now = t0.Add(time.Hour)
		if n := h.svc.ExpireDue(); n != 1 {
			t.Fatalf("expired %d", n)
		}
		if m := g.muts(); !slices.Equal(m, []string{"REMOVE " + g.g1 + " " + g.member}) {
			t.Errorf("changes at expiry = %v", m)
		}
		if g.in(g.g1) || !g.in(g.g2) {
			t.Errorf("after expiry: g1=%v g2=%v", g.in(g.g1), g.in(g.g2))
		}
		cur := h.svc.Request(r.ID)
		if g.grant(cur).RemovedAt == nil || cur.Enforcement.RemovedAt == nil {
			t.Errorf("removal not recorded: %+v %+v", g.grant(cur), cur.Enforcement)
		}
		h.svc.ExpireDue()
		if m := g.muts(); len(m) != 0 {
			t.Errorf("a later tick changed something: %v", m)
		}
	})
}

// Two running requests for the same group share one membership. It comes
// off when the last of them ends.
func TestGroupsSharedMembership(t *testing.T) {
	eachProvider(t, func(t *testing.T, g *groupRig) {
		h := g.h
		w1 := h.workflow(t, g.flow("one", "", g.g1))
		w2 := h.workflow(t, g.flow("two", "", g.g1, g.g2))
		a, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w1.ID, Duration: Duration(30 * time.Minute), Reason: "a"})
		b, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w2.ID, Duration: Duration(2 * time.Hour), Reason: "b"})
		if _, err := h.svc.Approve(ctx, bob, a.ID, ""); err != nil {
			t.Fatal(err)
		}
		gb, err := h.svc.Approve(ctx, bob, b.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		if gr := g.grant(gb); len(gr.Preexisting) != 0 || len(gr.Added) != 2 {
			t.Errorf("second grant = %+v", gr)
		}
		g.muts()
		h.now = t0.Add(30 * time.Minute)
		h.svc.ExpireDue()
		if m := g.muts(); len(m) != 0 || !g.in(g.g1) {
			t.Errorf("the first expiry removed a shared membership: %v", m)
		}
		if _, err := h.svc.Revoke(ctx, alice, b.ID, ""); err != nil {
			t.Fatal(err)
		}
		if g.in(g.g1) || g.in(g.g2) {
			t.Errorf("revoke left memberships: %v", g.muts())
		}
	})
}

// An approval that cannot finish leaves nothing behind, whichever step
// failed: a later group, or the posture attribute.
func TestGroupsFailedApprovalIsTakenBack(t *testing.T) {
	eachProvider(t, func(t *testing.T, g *groupRig) {
		for _, step := range []string{"group", "attribute"} {
			t.Run(step, func(t *testing.T) {
				h := g.h
				w := h.workflow(t, g.flow("admin "+step, "aws_"+step, g.g1, g.g2))
				r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
				if step == "group" {
					g.fail["add:"+g.g2] = errors.New("refused")
				} else {
					h.ts.fail["custom:jit_aws_"+step] = errors.New("tailscale down")
				}
				got, err := h.svc.Approve(ctx, bob, r.ID, "")
				if code(err) != "tailscale_api_error" || got.Status != StatusPending || g.grant(got) != nil || len(got.Attributes) != 0 {
					t.Fatalf("approve = %v %+v", err, got)
				}
				if g.in(g.g1) || g.in(g.g2) || g.kind.intent(h.svc.Request(r.ID)) != nil {
					t.Errorf("left behind: g1=%v g2=%v intent=%+v", g.in(g.g1), g.in(g.g2), g.kind.intent(h.svc.Request(r.ID)))
				}
				delete(g.fail, "add:"+g.g2)
				delete(h.ts.fail, "custom:jit_aws_"+step)
				if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || got.Status != StatusApproved || !g.in(g.g1) || !g.in(g.g2) {
					t.Fatalf("retry = %v %+v", err, got)
				}
				if _, err := h.svc.Revoke(ctx, bob, r.ID, ""); err != nil || g.in(g.g1) || g.in(g.g2) {
					t.Fatalf("revoke = %v, g1=%v g2=%v", err, g.in(g.g1), g.in(g.g2))
				}
			})
		}
	})
}

// jitd stops after it added the member and before the approval was saved.
// The membership is on record, so the next tick takes it back.
func TestGroupsUnfinishedApprovalIsTakenBack(t *testing.T) {
	eachProvider(t, func(t *testing.T, g *groupRig) {
		h := g.h
		w := h.workflow(t, g.flow("admin", "", g.g1))
		r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
		out := h.svc.planGroups(ctx, g.provider(), r)
		if out.err == nil {
			h.svc.writeGroups(ctx, r, out)
		}
		if out.err != nil {
			t.Fatal(out.err)
		}
		cur := h.svc.Request(r.ID)
		if !g.in(g.g1) || cur.Status != StatusPending || g.kind.intent(cur) == nil || g.grant(cur) != nil {
			t.Fatalf("after the unfinished approval: member=%v %s intent=%+v", g.in(g.g1), cur.Status, g.kind.intent(cur))
		}
		h.svc.ExpireDue()
		cur = h.svc.Request(r.ID)
		if g.in(g.g1) || g.kind.intent(cur) != nil || cur.Status != StatusPending {
			t.Fatalf("after the tick: member=%v %s intent=%+v", g.in(g.g1), cur.Status, g.kind.intent(cur))
		}
		if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || !slices.Equal(g.grant(got).Added, []string{g.g1}) || !g.in(g.g1) {
			t.Errorf("approve afterwards = %v %+v", err, got)
		}
	})
}

// A removal that fails is retried; one that keeps failing is put in front
// of the admins, once, and cleared when it goes through.
func TestGroupsStuckRemoval(t *testing.T) {
	eachProvider(t, func(t *testing.T, g *groupRig) {
		h := g.h
		rec := &recorder{}
		h.svc.Notify = rec
		w := h.workflow(t, g.flow("admin", "aws", g.g1))
		r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
		h.svc.Approve(ctx, bob, r.ID, "")
		g.fail["remove:"+g.g1] = errors.New("403 forbidden")
		got, err := h.svc.Revoke(ctx, bob, r.ID, "")
		if err != nil || got.Status != StatusRevoked || g.grant(got).RemovedAt != nil || !strings.Contains(g.grant(got).Error, "403 forbidden") {
			t.Fatalf("revoke = %v %+v", err, g.grant(got))
		}
		problems := func() []GroupProblem { return h.svc.groupProblems(g.provider()) }
		h.now = t0.Add(time.Minute)
		h.svc.ExpireDue()
		if cur := h.svc.Request(r.ID); g.kind.stuckOn(cur) || eventCount(rec, g.kind.stuck) != 0 || len(problems()) != 0 || !g.in(g.g1) {
			t.Fatalf("after a minute: %+v, problems %+v", g.grant(cur), problems())
		}
		h.now = t0.Add(6 * time.Minute)
		h.svc.ExpireDue()
		h.now = t0.Add(7 * time.Minute)
		h.svc.ExpireDue()
		cur := h.svc.Request(r.ID)
		if !g.kind.stuckOn(cur) || !cur.GroupsStuck() || eventCount(rec, g.kind.stuck) != 1 {
			t.Fatalf("after six minutes: %+v, events %v", g.grant(cur), rec.list())
		}
		if ps := problems(); len(ps) != 1 || ps[0].RequestID != r.ID || !strings.Contains(ps[0].Text, "403 forbidden") || !strings.Contains(ps[0].Text, g.n1) {
			t.Errorf("problems = %+v", ps)
		}
		delete(g.fail, "remove:"+g.g1)
		h.now = t0.Add(8 * time.Minute)
		h.svc.ExpireDue()
		cur = h.svc.Request(r.ID)
		if g.in(g.g1) || g.grant(cur).RemovedAt == nil || cur.GroupsStuck() || len(problems()) != 0 || eventCount(rec, g.kind.cleared) != 1 {
			t.Fatalf("after it went through: member=%v %+v problems=%+v events=%v", g.in(g.g1), g.grant(cur), problems(), rec.list())
		}
	})
}

// Someone takes the member out while the access is running. jitd notes it
// and does not add them back.
func TestGroupsNoteWhatWentMissing(t *testing.T) {
	eachProvider(t, func(t *testing.T, g *groupRig) {
		h := g.h
		w := h.workflow(t, g.flow("admin", "", g.g1, g.g2))
		r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x", Duration: Duration(2 * time.Hour)})
		h.svc.Approve(ctx, bob, r.ID, "")
		h.svc.ExpireDue()
		if cur := h.svc.Request(r.ID); g.grant(cur).CheckedAt == nil || len(g.grant(cur).Missing) != 0 {
			t.Fatalf("first comparison: %+v", g.grant(cur))
		}
		g.take(g.g1)
		h.now = t0.Add(11 * time.Minute)
		h.svc.ExpireDue()
		cur := h.svc.Request(r.ID)
		if !slices.Equal(g.grant(cur).Missing, []string{g.g1}) {
			t.Fatalf("missing = %v", g.grant(cur).Missing)
		}
		var set GroupSet
		for _, s := range cur.GroupSets() {
			if s.Key == g.kind.key {
				set = s
			}
		}
		if !slices.Equal(set.Missing(), []string{g.n1}) || len(set.Added()) != 2 {
			t.Errorf("shown as missing %v, added %v", set.Missing(), set.Added())
		}
		if g.in(g.g1) || !g.in(g.g2) || len(g.muts()) != 0 {
			t.Errorf("jitd changed something: g1=%v g2=%v", g.in(g.g1), g.in(g.g2))
		}
		h.now = t0.Add(3 * time.Hour)
		h.svc.ExpireDue()
		if cur = h.svc.Request(r.ID); g.in(g.g2) || g.grant(cur).RemovedAt == nil {
			t.Errorf("after expiry: g2=%v %+v", g.in(g.g2), g.grant(cur))
		}
	})
}

// Google only.

func TestGoogleFlowValidation(t *testing.T) {
	h, _ := googleHarness(t)
	// A group is named by its address; jitd keeps its ID with it. The
	// address and the ID of one group collapse.
	w, err := h.svc.CreateWorkflow(googleFlow(GroupRef{Name: "AWS-Admin@Example.com"}, GroupRef{Name: ggAdmin}))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.GoogleGroups) != 1 || w.GoogleGroups[0] != (GroupRef{ID: ggAdmin, Name: gaAdmin}) || w.Attribute != "" {
		t.Errorf("flow = %+v", w.GoogleGroups)
	}
	if got := h.svc.Requestable(ctx, alice); len(got) != 1 || len(got[0].GoogleGroups) != 1 {
		t.Errorf("requestable = %+v", got)
	}
	_, err = h.svc.CreateWorkflow(googleFlow(GroupRef{Name: "nobody@example.com"}))
	if code(err) != "bad_request" || !strings.Contains(err.Error(), "Groups Admin") || strings.Contains(err.Error(), "by its email address") {
		t.Errorf("unknown group: %v", err)
	}
	if _, err = h.svc.CreateWorkflow(googleFlow(GroupRef{Name: "aws-admin"})); code(err) != "bad_request" || !strings.Contains(err.Error(), "by its email address") {
		t.Errorf("a group named without its domain: %v", err)
	}
	if _, err = h.svc.CreateWorkflow(googleFlow(GroupRef{Name: "all-eng@example.com"})); code(err) != "bad_request" || !strings.Contains(err.Error(), "dynamic") {
		t.Errorf("dynamic group: %v", err)
	}
	// The allowlist is by address or ID.
	h.svc.GoogleLimits = func() GoogleLimits {
		return GoogleLimits{Grant: []string{"aws-read@*"}, Domains: []string{"example.com"}}
	}
	other := googleFlow(GroupRef{Name: gaAdmin})
	other.Name = "not allowed"
	if _, err = h.svc.CreateWorkflow(other); code(err) != "forbidden" || !strings.Contains(err.Error(), "Google page") {
		t.Errorf("group off the allowlist: %v", err)
	}
	other.GoogleGroups = []GroupRef{{Name: gaRead}}
	if _, err = h.svc.CreateWorkflow(other); err != nil {
		t.Errorf("group on the allowlist: %v", err)
	}
	if c, err := h.svc.CheckGoogleGroup(ctx, gaAdmin); err != nil || c.ID != ggAdmin || !c.Manageable || c.GrantAllowed {
		t.Errorf("check = %+v %v", c, err)
	}
	if c, err := h.svc.CheckGoogleGroup(ctx, "all-eng@example.com"); err != nil || c.Manageable {
		t.Errorf("check of a dynamic group = %+v %v", c, err)
	}
	if _, err := h.svc.CheckGoogleGroup(ctx, "nobody@example.com"); code(err) != "not_found" {
		t.Errorf("check of an unknown group: %v", err)
	}
	// Without Google, flows with Google groups are refused.
	h.svc.Google = nil
	off := googleFlow(GroupRef{Name: gaRead})
	off.Name = "off"
	if _, err = h.svc.CreateWorkflow(off); code(err) != "conflict" || !strings.Contains(err.Error(), "Google page") {
		t.Errorf("unconfigured: %v", err)
	}
}

// Only logins in the allowed domains are added: anyone else would become
// an outside member wherever a group allows those.
func TestGoogleAllowedDomains(t *testing.T) {
	for name, lim := range map[string]func() GoogleLimits{
		"other domain": func() GoogleLimits { return GoogleLimits{Domains: []string{"corp.example"}} },
		"no domains":   func() GoogleLimits { return GoogleLimits{} },
		"no limits":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			h, f := googleHarness(t)
			w := h.workflow(t, googleFlow(GroupRef{Name: gaAdmin}))
			h.svc.GoogleLimits = lim
			r, err := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
			if err != nil {
				t.Fatal(err)
			}
			got, err := h.svc.Approve(ctx, bob, r.ID, "")
			if err == nil || got.Status != StatusPending || got.Google != nil || len(f.Mutations()) != 0 {
				t.Fatalf("approve = %v %+v", err, got)
			}
			if name == "other domain" && !strings.Contains(got.LastError, "allowed domains") {
				t.Errorf("error = %q", got.LastError)
			}
		})
	}
	lim := ParseGoogleLimits(map[string]string{google.EnvDomains: " Example.com, @corp.example ,example.com"})
	if !slices.Equal(lim.Domains, []string{"example.com", "corp.example"}) || !AllowsAll(lim.Grant) {
		t.Errorf("limits = %+v", lim)
	}
	if lim := ParseGoogleLimits(map[string]string{google.EnvGrantAllowlist: ""}); lim.Grant == nil || len(lim.Grant) != 0 || len(lim.Domains) != 0 {
		t.Errorf("an empty allowlist = %+v", lim)
	}
}

// Flows with groups of both kinds.

func bothHarness(t *testing.T) (*harness, *okta.Fake, *google.Fake) {
	t.Helper()
	h, o := oktaHarness(t)
	return h, o, addGoogle(h)
}

func bothFlow(attr string) Workflow {
	w := oktaFlow(OktaGroup{ID: gAdmin})
	w.Name, w.Attribute, w.GoogleGroups = "AWS and Cloud admin", attr, []GroupRef{{ID: ggAdmin}}
	return w
}

// One approval adds the requester on both sides, Google first. Each side
// ends on its own: a removal that fails with one does not hold up the
// other, and the request is only done when both are.
func TestBothKindsGrantAndEndIndependently(t *testing.T) {
	h, o, g := bothHarness(t)
	var order []string
	o.Hook = func(call string) {
		if call == "add" {
			order = append(order, "okta")
		}
	}
	g.Hook = func(call string) {
		if call == "add" {
			order = append(order, "google")
		}
	}
	w := h.workflow(t, bothFlow(""))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, []string{"google", "okta"}) || !o.Member(gAdmin, uAlice) || !g.Member(ggAdmin, mAlice) {
		t.Fatalf("order %v, okta=%v google=%v", order, o.Member(gAdmin, uAlice), g.Member(ggAdmin, mAlice))
	}
	if got.Okta == nil || got.Google == nil || got.Google.UserID != mAlice || got.Enforcement.ConfirmedAt == nil || got.OktaAdding != nil || got.GoogleAdding != nil {
		t.Fatalf("approved: okta=%+v google=%+v", got.Okta, got.Google)
	}
	if sets := got.GroupSets(); len(sets) != 2 || sets[0].Label != "Okta" || sets[1].Label != "Google" || !slices.Equal(sets[1].Added(), []string{gaAdmin}) {
		t.Errorf("sets = %+v", sets)
	}

	g.Fail["remove:"+ggAdmin] = errors.New("google down")
	got, err = h.svc.Revoke(ctx, bob, r.ID, "")
	if err != nil || got.Status != StatusRevoked {
		t.Fatalf("revoke = %v %+v", err, got)
	}
	if o.Member(gAdmin, uAlice) || got.Okta.RemovedAt == nil {
		t.Errorf("Okta's removal waited for Google's: %+v", got.Okta)
	}
	if !g.Member(ggAdmin, mAlice) || got.Google.RemovedAt != nil || got.Enforcement.RemovedAt != nil || !got.GroupsRemovalPending() {
		t.Errorf("with Google failing: google=%+v enforcement=%+v", got.Google, got.Enforcement)
	}
	h.now = t0.Add(10 * time.Minute)
	h.svc.ExpireDue()
	h.now = t0.Add(11 * time.Minute)
	h.svc.ExpireDue()
	if ps := h.svc.GoogleProblems(); len(ps) != 1 || ps[0].RequestID != r.ID {
		t.Errorf("Google problems = %+v", ps)
	}
	if ps := h.svc.OktaProblems(); len(ps) != 0 {
		t.Errorf("Okta problems = %+v", ps)
	}
	delete(g.Fail, "remove:"+ggAdmin)
	h.now = t0.Add(12 * time.Minute)
	h.svc.ExpireDue()
	cur := h.svc.Request(r.ID)
	if g.Member(ggAdmin, mAlice) || cur.Google.RemovedAt == nil || cur.Enforcement.RemovedAt == nil || cur.GroupsRemovalPending() || len(h.svc.GoogleProblems()) != 0 {
		t.Errorf("after Google recovered: google=%+v enforcement=%+v", cur.Google, cur.Enforcement)
	}
}

// Google uses up its time in a tick (here: the tick's context ends while
// Google's removal runs). Okta's removal is still made in that tick, not
// left for one in which Google happens to be quick.
func TestGoogleUsingUpTheTickDoesNotStarveOkta(t *testing.T) {
	h, o, g := bothHarness(t)
	w := h.workflow(t, bothFlow(""))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Duration: Duration(time.Hour), Reason: "x"})
	if _, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	h.now = t0.Add(time.Hour)
	if n := h.svc.expireDue(); n != 1 {
		t.Fatalf("expired %d", n)
	}
	tick, cancel := context.WithCancel(ctx)
	defer cancel()
	g.Hook = func(call string) {
		if call == "remove" {
			cancel()
		}
	}
	h.svc.groupUpkeep(tick)
	cur := h.svc.Request(r.ID)
	if o.Member(gAdmin, uAlice) || cur.Okta.RemovedAt == nil {
		t.Errorf("Okta's removal waited for another tick: member=%v okta=%+v", o.Member(gAdmin, uAlice), cur.Okta)
	}
	if g.Member(ggAdmin, mAlice) || cur.Google.RemovedAt == nil {
		t.Errorf("Google's removal: member=%v google=%+v", g.Member(ggAdmin, mAlice), cur.Google)
	}
}

// The second provider refuses: what the first already added is taken back
// and nothing is recorded as granted.
func TestBothKindsSecondProviderFails(t *testing.T) {
	h, o, g := bothHarness(t)
	w := h.workflow(t, bothFlow("aws"))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	o.Fail["add:"+gAdmin] = errors.New("E0000006 forbidden")
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if code(err) != "tailscale_api_error" || got.Status != StatusPending || got.Okta != nil || got.Google != nil || len(got.Attributes) != 0 {
		t.Fatalf("approve = %v %+v", err, got)
	}
	if m := g.Mutations(); !slices.Equal(m, []string{"ADD " + ggAdmin + " " + mAlice, "REMOVE " + ggAdmin + " " + mAlice}) {
		t.Errorf("Google changes = %v", m)
	}
	if cur := h.svc.Request(r.ID); g.Member(ggAdmin, mAlice) || cur.GoogleAdding != nil || cur.OktaAdding != nil {
		t.Errorf("left behind: member=%v google=%+v okta=%+v", g.Member(ggAdmin, mAlice), cur.GoogleAdding, cur.OktaAdding)
	}
	delete(o.Fail, "add:"+gAdmin)
	if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || got.Status != StatusApproved || !o.Member(gAdmin, uAlice) || !g.Member(ggAdmin, mAlice) {
		t.Fatalf("retry = %v %+v", err, got)
	}
}

// A requester one provider will not take is found before the other has
// added them.
func TestBothKindsPlanBeforeAnyChange(t *testing.T) {
	h, o, g := bothHarness(t)
	fl := bothFlow("")
	fl.AllowSelfApproval = true
	w := h.workflow(t, fl)
	r, _ := h.svc.Submit(ctx, bob, NewRequest{WorkflowID: w.ID, Reason: "x"}) // bob has no Okta user
	got, err := h.svc.Approve(ctx, bob, r.ID, "")
	if err == nil || got.Status != StatusPending || !strings.Contains(got.LastError, "Okta user") {
		t.Fatalf("approve = %v %+v", err, got)
	}
	if len(g.Mutations()) != 0 || len(o.Mutations()) != 0 {
		t.Error("something was changed for a requester Okta does not know")
	}
}

// jitd stops between the two providers: Google has the member, Okta was not
// reached, nothing is saved as granted. Google's membership is on record
// and the next tick takes it back.
func TestBothKindsStopBetweenProviders(t *testing.T) {
	h, o, g := bothHarness(t)
	w := h.workflow(t, bothFlow(""))
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	ps := h.svc.providers()
	if ps[0].groupKind != googleKind {
		t.Fatalf("the first provider written is %s", ps[0].key)
	}
	out := h.svc.planGroups(ctx, ps[0], r)
	if out.err == nil {
		h.svc.writeGroups(ctx, r, out)
	}
	if out.err != nil {
		t.Fatal(out.err)
	}
	cur := h.svc.Request(r.ID)
	if !g.Member(ggAdmin, mAlice) || o.Member(gAdmin, uAlice) || cur.GoogleAdding == nil || cur.Google != nil {
		t.Fatalf("after the stop: google member=%v intent=%+v", g.Member(ggAdmin, mAlice), cur.GoogleAdding)
	}
	h.svc.ExpireDue()
	cur = h.svc.Request(r.ID)
	if g.Member(ggAdmin, mAlice) || cur.GoogleAdding != nil || cur.Status != StatusPending {
		t.Fatalf("after the tick: member=%v intent=%+v %s", g.Member(ggAdmin, mAlice), cur.GoogleAdding, cur.Status)
	}
	if got, err := h.svc.Approve(ctx, bob, r.ID, ""); err != nil || !o.Member(gAdmin, uAlice) || !g.Member(ggAdmin, mAlice) || got.Status != StatusApproved {
		t.Errorf("approve afterwards = %v %+v", err, got)
	}
}

// What a request with Okta groups alone shows did not change with Google.
func TestGroupSetsOktaOnly(t *testing.T) {
	h, _ := oktaHarness(t)
	w := h.workflow(t, oktaFlow(OktaGroup{ID: gAdmin}))
	if sets := w.GroupSets(); len(sets) != 1 || sets[0].Label != "Okta" || !slices.Equal(sets[0].Labels(), []string{"AWS-Prod-Admin"}) {
		t.Errorf("flow sets = %+v", sets)
	}
	r, _ := h.svc.Submit(ctx, alice, NewRequest{WorkflowID: w.ID, Reason: "x"})
	got, _ := h.svc.Approve(ctx, bob, r.ID, "")
	sets := got.GroupSets()
	if len(sets) != 1 || sets[0].Key != "okta" || !slices.Equal(sets[0].Added(), got.OktaAddedLabels()) || sets[0].RemovalPending() || sets[0].Stuck() {
		t.Fatalf("sets = %+v", sets)
	}
	got, _ = h.svc.Revoke(ctx, bob, r.ID, "")
	if s := got.GroupSets()[0]; !slices.Equal(s.Removed(), got.OktaRemovedLabels()) || len(s.Removed()) != 1 || len(s.Kept()) != 0 {
		t.Errorf("after revoke: removed %v kept %v", s.Removed(), s.Kept())
	}
}
