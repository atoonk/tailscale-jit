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
	if err != nil || got.Status != StatusRevoked || got.Okta.RemovedAt != nil || !strings.Contains(got.LastError, "rate limited") {
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
	if l := ParseOktaAllowlist(map[string]string{EnvOktaReadAllowlist: " , "}); fmt.Sprint(l.Grant) != "[*]" || fmt.Sprint(l.Read) != "[*]" || !AllowsAll(l.Grant) {
		t.Errorf("defaults = %+v", l)
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
