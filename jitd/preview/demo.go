package main

import (
	"context"
	"slices"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// The demo cast, for screenshots and videos: made-up people at example.com.
// Maya is a backend engineer whose Claude Code files requests from her
// laptop; Sam and Priya are the SREs who approve; Leo (security) is the
// admin.
var demoPeople = map[string]jit.Identity{
	"maya":  {Login: "maya.chen@example.com", DisplayName: "Maya Chen", DeviceID: "nMAYA", DeviceName: "maya-macbook"},
	"sam":   {Login: "sam.rivera@example.com", DisplayName: "Sam Rivera", DeviceID: "nSAM", DeviceName: "sam-thinkpad"},
	"priya": {Login: "priya.natarajan@example.com", DisplayName: "Priya Natarajan", DeviceID: "nPRIYA", DeviceName: "priya-mbp"},
	"leo":   {Login: "leo.park@example.com", DisplayName: "Leo Park", DeviceID: "nLEO", DeviceName: "leo-laptop"},
}

var demoAdmins = []jit.Principal{"leo.park@example.com"}

var (
	sre    = []jit.Principal{"group:sre"}
	member = []jit.Principal{"autogroup:member"}
)

// demoFlows are the approval flows of the demo tailnet. Kubernetes is the
// one an admin has just added: it is not in the policy yet.
func demoFlows() []jit.Workflow {
	h := func(n int) jit.Duration { return jit.Duration(time.Duration(n) * time.Hour) }
	mysql1 := jit.Resource{Name: "svc:mysql-server-1", Description: "Catalog database: books and titles (MySQL, production)"}
	mysql2 := jit.Resource{Name: "svc:mysql-server-2", Description: "Orders and customers (MySQL, production)"}
	logs := jit.Resource{Name: "svc:elasticsearch-logs", Description: "Application logs (Elasticsearch)"}
	return []jit.Workflow{
		{Name: "Database access (read-only)", Description: "SELECT on the production databases and the logs", Attribute: "db_ro",
			Resources: []jit.Resource{mysql1, mysql2, logs}, Requesters: member, Approvers: sre,
			MaxDuration: h(4), DefaultDuration: h(1)},
		{Name: "Database access (read-write)", Description: "Writes to production; two approvals", Attribute: "db_rw",
			Resources: []jit.Resource{mysql1, mysql2}, Requesters: member, Approvers: []jit.Principal{"group:sre", "leo.park@example.com"}, ApprovalsRequired: 2,
			MaxDuration: h(1), DefaultDuration: jit.Duration(30 * time.Minute)},
		{Name: "SSH access", Description: "Shell, exec and SFTP on the bastion and ops hosts", Attribute: "ssh",
			Resources:  []jit.Resource{{Name: "svc:ssh-bastion", Description: "Jump host (us-east-1)"}, {Name: "svc:ssh-ops-1", Description: "Ops box: cron jobs and backups"}},
			Requesters: member, Approvers: sre, MaxDuration: h(8), DefaultDuration: h(2)},
		{Name: "Windows jump host", Description: "RDP to the Windows admin host", Attribute: "rdp",
			Resources:  []jit.Resource{{Name: "svc:windows-jump-host", Description: "Windows Server 2022 admin host"}},
			Requesters: member, Approvers: sre, MaxDuration: h(4), DefaultDuration: h(1)},
		{Name: "Production SSH (break-glass)", Description: "Root on every production host; two approvals, keep it short", Attribute: "prod_ssh",
			Resources:  []jit.Resource{{Name: "tag:prod", Description: "All production hosts"}},
			Requesters: sre, Approvers: []jit.Principal{"group:sre", "leo.park@example.com"}, ApprovalsRequired: 2,
			MaxDuration: h(1), DefaultDuration: jit.Duration(30 * time.Minute)},
		{Name: "Kubernetes (read-only)", Description: "kubectl get, describe and logs on the production cluster", Attribute: "k8s_ro",
			Resources:  []jit.Resource{{Name: "svc:kubernetes-prod-cluster", Description: "Production cluster API (EKS, us-east-1)"}},
			Requesters: member, Approvers: sre, MaxDuration: h(8), DefaultDuration: h(2)},
	}
}

// demoPolicy is the demo tailnet's policy: every flow but Kubernetes has its
// posture and grant.
func demoPolicy() *tsapi.Policy {
	p := &tsapi.Policy{
		Groups:    map[string][]string{"group:sre": {"sam.rivera@example.com", "priya.natarajan@example.com"}},
		Postures:  map[string][]string{},
		TagOwners: map[string][]string{"tag:jit": {"autogroup:admin"}},
		Grants:    []tsapi.Grant{{Src: []string{"autogroup:member"}, Dst: []string{"tag:jit"}}},
	}
	for _, w := range demoFlows() {
		if w.Attribute == "k8s_ro" {
			continue
		}
		w.Normalize()
		p.Postures[w.Posture()] = []string{w.Attribute + " == true"}
		src := make([]string, len(w.Requesters))
		for i, r := range w.Requesters {
			src[i] = string(r)
		}
		p.Grants = append(p.Grants, tsapi.Grant{Src: src, Dst: w.ResourceNames(), SrcPosture: []string{w.Posture()}})
	}
	return p
}

// seedDemo creates the flows and two weeks of history, moving the service's
// clock so timestamps, expiries and the activity chart look lived in.
func seedDemo(svc *jit.Service) {
	ctx := context.Background()
	end := time.Now().UTC()
	clock := end.Add(-14 * 24 * time.Hour).Truncate(time.Hour).Add(9 * time.Hour)
	svc.Now = func() time.Time { return clock }
	defer func() { svc.Now = nil }()
	// Expiries are processed shortly after they happen, as the real expiry
	// tick does, before the clock jumps to the next event.
	var expiries []time.Time
	moveTo := func(t time.Time) {
		slices.SortFunc(expiries, func(a, b time.Time) int { return a.Compare(b) })
		for len(expiries) > 0 && !expiries[0].After(t) {
			clock = expiries[0].Add(25 * time.Second)
			svc.ExpireDue()
			expiries = expiries[1:]
		}
		clock = t
		svc.ExpireDue()
	}
	at := func(daysAgo int, hhmm string) {
		t, _ := time.Parse("15:04", hhmm)
		d := end.Add(-time.Duration(daysAgo) * 24 * time.Hour)
		moveTo(time.Date(d.Year(), d.Month(), d.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC))
	}

	flows := map[string]*jit.Workflow{}
	for _, w := range demoFlows() {
		out, err := svc.CreateWorkflow(w)
		if err != nil {
			panic(err)
		}
		flows[w.Attribute] = out
	}
	p := demoPeople
	submit := func(who, flow string, dur time.Duration, reason string) *jit.AccessRequest {
		r, err := svc.Submit(ctx, p[who], jit.NewRequest{WorkflowID: flows[flow].ID, Duration: jit.Duration(dur), Reason: reason})
		if err != nil {
			panic(who + " " + flow + ": " + err.Error())
		}
		return r
	}
	approve := func(who string, r *jit.AccessRequest, note string) {
		out, err := svc.Approve(ctx, p[who], r.ID, note)
		if err != nil {
			panic("approve " + r.ID + ": " + err.Error())
		}
		if out.ExpiresAt != nil {
			expiries = append(expiries, *out.ExpiresAt)
		}
	}
	later := func(d time.Duration) { clock = clock.Add(d) }

	type step struct {
		day             int
		hhmm, who, flow string
		dur             time.Duration
		reason          string
		approver, note  string // "" leaves it pending; "decline:" prefix in note declines
		wait            time.Duration
	}
	steps := []step{
		{13, "09:12", "maya", "db_ro", time.Hour, "Check order totals for the finance reconciliation", "sam", "", 4 * time.Minute},
		{13, "14:40", "priya", "db_ro", 2 * time.Hour, "Profile the slow customer search query", "sam", "", 9 * time.Minute},
		{12, "10:05", "sam", "ssh", 2 * time.Hour, "Rotate the log shipper config on the bastion", "priya", "", 3 * time.Minute},
		{11, "16:20", "maya", "db_rw", 30 * time.Minute, "Backfill order statuses after the failed migration", "sam", "", 6 * time.Minute},
		{10, "08:55", "leo", "rdp", time.Hour, "Review GPO changes on the Windows admin host", "sam", "", 12 * time.Minute},
		{10, "13:30", "maya", "db_ro", time.Hour, "Debug INC-4790: missing invoices", "priya", "", 2 * time.Minute},
		{9, "11:00", "priya", "db_rw", time.Hour, "Drop the unused staging columns", "sam", "decline:Do this through a reviewed migration, not by hand", 20 * time.Minute},
		{8, "09:40", "sam", "prod_ssh", 30 * time.Minute, "INC-4801: disk full on api-3, need root to clear it", "priya", "", 5 * time.Minute},
		{7, "15:15", "maya", "ssh", 2 * time.Hour, "Check the cron job that sends order emails", "sam", "", 7 * time.Minute},
		{6, "10:30", "priya", "db_ro", 4 * time.Hour, "Build the weekly retention report", "sam", "", 15 * time.Minute},
		{5, "09:05", "maya", "db_ro", time.Hour, "Verify the refund job wrote the right totals", "priya", "", 3 * time.Minute},
		{4, "17:45", "leo", "db_ro", time.Hour, "Audit who changed the customer export settings", "sam", "", 8 * time.Minute},
		{3, "11:20", "sam", "ssh", time.Hour, "Patch openssl on the ops box", "priya", "", 4 * time.Minute},
		{2, "14:00", "maya", "db_rw", 30 * time.Minute, "Fix three orders stuck in 'processing'", "sam", "", 11 * time.Minute},
		{1, "10:10", "priya", "db_ro", 2 * time.Hour, "Investigate the spike in failed payments", "sam", "", 6 * time.Minute},
	}
	for _, st := range steps {
		at(st.day, st.hhmm)
		r := submit(st.who, st.flow, st.dur, st.reason)
		later(st.wait)
		switch {
		case len(st.note) > 8 && st.note[:8] == "decline:":
			if _, err := svc.Decline(ctx, p[st.approver], r.ID, st.note[8:]); err != nil {
				panic(err)
			}
		case flows[st.flow].ApprovalsRequired > 1:
			// Two approvals: the other SRE (or Leo) gives the second.
			second := map[string]string{"sam": "priya", "priya": "sam"}[st.approver]
			if second == "" || second == st.who {
				second = "leo"
			}
			approve(st.approver, r, st.note)
			later(2 * time.Minute)
			approve(second, r, "")
		default:
			approve(st.approver, r, st.note)
		}
	}
	// Today: Sam has SSH running; Priya waits on a second approval for a
	// write; Maya's agent will file the request the demo is about.
	now := func(ago time.Duration) { moveTo(end.Add(-ago)) }
	now(50 * time.Minute)
	r := submit("sam", "ssh", 2*time.Hour, "Investigate high load on the ops box")
	later(3 * time.Minute)
	approve("priya", r, "")
	now(25 * time.Minute)
	r = submit("priya", "db_rw", 30*time.Minute, "Correct the tax rate on two EU orders (TICKET-2231)")
	later(4 * time.Minute)
	approve("sam", r, "Checked the ticket")
}
