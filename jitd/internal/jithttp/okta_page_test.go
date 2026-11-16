package jithttp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// A removal from Okta that keeps failing shows to admins on every page and
// on the request itself; other people see it on the request only.
func TestOktaProblemsShown(t *testing.T) {
	const group = "00gADMIN000000000001"
	of := okta.NewFake()
	of.AddUser("00uALICE", "alice@example.com")
	of.AddGroup(group, "AWS-Prod-Admin", "")
	now := time.Now().UTC()
	srv, _, h := newTestServerWith(t, func(s *Server) {
		s.Svc.Okta = of
		s.Svc.Now = func() time.Time { return now }
	})
	w, err := h.Svc.CreateWorkflow(jit.Workflow{
		Name: "AWS admin", Attribute: "aws", OktaGroups: []jit.OktaGroup{{ID: group}},
		Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"bob@example.com"},
		MaxDuration: jit.Duration(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.Svc.Submit(t.Context(), people["alice"], jit.NewRequest{WorkflowID: w.ID, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Svc.Approve(t.Context(), people["bob"], r.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, body := getPage(t, srv, "root", "/"); strings.Contains(body, "okta-problems") {
		t.Fatal("banner with nothing wrong")
	}
	of.Fail["remove:"+group] = errors.New("403 forbidden")
	if _, err := h.Svc.Revoke(t.Context(), people["bob"], r.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, body := getPage(t, srv, "alice", "/requests/"+r.ID)
	if !strings.Contains(body, "Okta group membership not yet removed, failing since") || !strings.Contains(body, "403 forbidden") {
		t.Errorf("the request page does not say the Okta removal is pending")
	}
	now = now.Add(6 * time.Minute)
	h.Svc.ExpireDue()
	_, body = getPage(t, srv, "root", "/")
	for _, want := range []string{`id="okta-problems"`, "alice@example.com is still in AWS-Prod-Admin", "403 forbidden", `href="/requests/` + r.ID + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the admin's page lacks %q", want)
		}
	}
	if _, body := getPage(t, srv, "alice", "/"); strings.Contains(body, "okta-problems") {
		t.Error("a non-admin sees the banner")
	}
	delete(of.Fail, "remove:"+group)
	now = now.Add(time.Minute)
	h.Svc.ExpireDue()
	if _, body := getPage(t, srv, "root", "/"); strings.Contains(body, "okta-problems") {
		t.Error("the banner stayed after the removal went through")
	}
}

// A request that ended while another of the same person holds the group
// does not claim the membership was taken away.
func TestKeptOktaGroupShown(t *testing.T) {
	const group = "00gADMIN000000000001"
	of := okta.NewFake()
	of.AddUser("00uALICE", "alice@example.com")
	of.AddGroup(group, "AWS-Prod-Admin", "")
	srv, _, h := newTestServerWith(t, func(s *Server) { s.Svc.Okta = of })
	var ids []string
	for _, name := range []string{"AWS admin", "AWS break-glass"} {
		w, err := h.Svc.CreateWorkflow(jit.Workflow{Name: name, OktaGroups: []jit.OktaGroup{{ID: group}},
			Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"bob@example.com"}, MaxDuration: jit.Duration(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		r, err := h.Svc.Submit(t.Context(), people["alice"], jit.NewRequest{WorkflowID: w.ID, Reason: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Svc.Approve(t.Context(), people["bob"], r.ID, ""); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	if _, err := h.Svc.Revoke(t.Context(), people["bob"], ids[0], ""); err != nil {
		t.Fatal(err)
	}
	if !of.Member(group, "00uALICE") {
		t.Fatal("the group the second request holds was removed")
	}
	_, page := getPage(t, srv, "root", "/requests/"+ids[0])
	if strings.Contains(page, "membership taken away") || !strings.Contains(page, "Still in the Okta group AWS-Prod-Admin through another running request") {
		t.Errorf("the ended request's page: kept group not shown, or claimed removed")
	}
	if _, err := h.Svc.Revoke(t.Context(), people["bob"], ids[1], ""); err != nil {
		t.Fatal(err)
	}
	if _, page := getPage(t, srv, "root", "/requests/"+ids[1]); !strings.Contains(page, "membership taken away") || of.Member(group, "00uALICE") {
		t.Errorf("the last request's page does not say the membership was taken away")
	}
}
