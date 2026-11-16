package slackbot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// An ended request whose Okta memberships jitd cannot remove: after a while
// every admin with a Slack account gets one direct message, the request's
// own messages carry a warning, and both change when the removal goes
// through.
func TestOktaStuckRemovalTellsAdmins(t *testing.T) {
	e := newEnv(t, nil)
	const group = "00gADMIN000000000001"
	of := okta.NewFake()
	of.AddUser("00uMAYA", "maya@example.com")
	of.AddGroup(group, "AWS-Prod-Admin", "")
	var mu sync.Mutex
	now := time.Now().UTC()
	clock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	e.svc.Okta = of
	e.svc.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	e.svc.Admins = []jit.Principal{"leo@example.com", "sam@example.com"} // leo is not on Slack

	w, err := e.svc.CreateWorkflow(jit.Workflow{
		Name: "AWS admin", OktaGroups: []jit.OktaGroup{{ID: group}},
		Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"priya@example.com"},
		MaxDuration: jit.Duration(time.Hour), Slack: &jit.WorkflowSlack{DMApprovers: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := e.svc.Submit(ctx, maya, jit.NewRequest{WorkflowID: w.ID, Reason: "rotate the deploy role"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the DM to the approver", func() bool { return len(e.svc.Request(r.ID).Slack) == 1 })
	priya := jit.Identity{Login: "priya@example.com"}
	if _, err := e.svc.Approve(ctx, priya, r.ID, ""); err != nil {
		t.Fatal(err)
	}
	of.Fail["remove:"+group] = errors.New("403 forbidden")
	if _, err := e.svc.Revoke(ctx, priya, r.ID, "done"); err != nil {
		t.Fatal(err)
	}
	e.svc.ExpireDue()
	if n := len(e.fake.PostsTo("DSAM")); n != 0 {
		t.Fatalf("an admin was told at the first failure (%d messages)", n)
	}

	clock(6 * time.Minute)
	e.svc.ExpireDue()
	waitFor(t, "the DM to the admin", func() bool { return len(e.fake.PostsTo("DSAM")) == 1 })
	js := blocksJSON(lastPost(t, e.fake, "DSAM").Message)
	for _, want := range []string{"Okta removal is failing", "maya@example.com", "AWS-Prod-Admin", "403 forbidden", "http://jit/requests/" + r.ID} {
		if !strings.Contains(js, want) {
			t.Errorf("the admin's message lacks %q: %s", want, js)
		}
	}
	waitFor(t, "the warning on the approver's message", func() bool {
		return strings.Contains(blocksJSON(lastPost(t, e.fake, "DPRIYA").Message), "still in the Okta group AWS-Prod-Admin")
	})

	// Told once: more failing ticks and a catch-up post nothing new.
	clock(time.Minute)
	e.svc.ExpireDue()
	e.bot.reconcile(ctx)
	time.Sleep(100 * time.Millisecond)
	if n := len(e.fake.PostsTo("DSAM")); n != 1 {
		t.Errorf("the admin got %d messages", n)
	}
	var kinds []string
	for _, m := range e.svc.Request(r.ID).Slack {
		kinds = append(kinds, m.Kind+":"+m.User)
	}
	if strings.Join(kinds, " ") != "dm:UPRIYA okta_alert:USAM" {
		t.Errorf("recorded messages = %v", kinds)
	}

	delete(of.Fail, "remove:"+group)
	clock(time.Minute)
	e.svc.ExpireDue()
	waitFor(t, "the all-clear to the admin", func() bool {
		return strings.Contains(blocksJSON(lastPost(t, e.fake, "DSAM").Message), "Okta removal went through")
	})
	waitFor(t, "the warning to go from the approver's message", func() bool {
		return !strings.Contains(blocksJSON(lastPost(t, e.fake, "DPRIYA").Message), "still in the Okta group")
	})
	if n := len(e.fake.PostsTo("DSAM")); n != 1 {
		t.Errorf("the all-clear was a new message (%d)", n)
	}
}
