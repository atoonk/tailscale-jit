package slackbot

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
)

// stallingAPI is the fake Slack whose views.open hangs until released, to
// hold a handler inside the socket's reader.
type stallingAPI struct {
	*slack.Fake
	entered, release chan struct{}
	once             sync.Once
}

func (a *stallingAPI) OpenView(ctx context.Context, trigger string, v slack.View) (string, error) {
	a.once.Do(func() { close(a.entered) })
	<-a.release
	return a.Fake.OpenView(ctx, trigger, v)
}

// within fails the test if f does not return in d.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

// Disconnecting while a handler runs in the socket's reader used to hold the
// bot's lock until the handler finished, and the handler needed that lock:
// the bot, and through RequestChanged every request action, hung for good.
func TestDisconnectWhileHandlerRuns(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	stall := &stallingAPI{Fake: e.fake, entered: make(chan struct{}), release: make(chan struct{})}
	e.bot.NewAPI = func(string, string) slack.API { return stall }
	if _, err := e.bot.Connect(context.Background(), leo, ConnectInput{BotToken: "xoxb-test-1234", AppToken: "xapp-test-5678", AllowedDomains: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reconnected", func() bool { return e.bot.Status().Connected() })

	// /jit request opens its form from inside the reader; it stalls there.
	e.fake.Send(slack.Command("USAM", "C0SREONCALL", "/jit", "request"))
	<-stall.entered

	disconnected := make(chan error, 1)
	go func() { disconnected <- e.bot.Disconnect(context.Background(), leo) }()
	time.Sleep(50 * time.Millisecond)

	// While the old socket winds down, jitd keeps working.
	within(t, 2*time.Second, "Status", func() { e.bot.Status() })
	within(t, 2*time.Second, "Submit", func() { e.submit(t, maya) })

	close(stall.release)
	select {
	case err := <-disconnected:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Disconnect did not return")
	}
}

// Slack users act as their Tailscale login only when that login is on the
// tailnet, their email is confirmed, and they belong to this workspace.
func TestSlackIdentityRules(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	everyone, err := e.svc.CreateWorkflow(jit.Workflow{Name: "Anyone approves", Attribute: "anyone",
		Requesters: []jit.Principal{"autogroup:member"}, Approvers: []jit.Principal{"autogroup:member"},
		MaxDuration: jit.Duration(time.Hour), Slack: &jit.WorkflowSlack{Channel: "C0SREONCALL"}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.Submit(context.Background(), maya, jit.NewRequest{WorkflowID: everyone.ID, Reason: "check a log"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "posted", func() bool { return len(e.fake.PostsTo("C0SREONCALL")) == 1 })
	ts := lastPost(t, e.fake, "C0SREONCALL").TS

	// Someone in the company's Slack but not on the tailnet (never was, or
	// offboarded) does not count as autogroup:member.
	e.fake.AddUser("UGONE", "gone@example.com", "Gone")
	e.fake.AddUser("UNOTCONF", "nc@example.com", "Unconfirmed")
	e.fake.SetUser("UNOTCONF", func(u *slack.User) { u.IsEmailConfirmed = false })
	e.fake.AddUser("UOTHER", "partner@example.com", "Partner")
	e.fake.SetUser("UOTHER", func(u *slack.User) { u.TeamID = "TPARTNER" })
	for _, u := range []string{"UGONE", "UNOTCONF", "UOTHER"} {
		e.fake.Send(slack.Interactive(u, "C0SREONCALL", ts, actionApprove, r.ID))
	}
	waitFor(t, "three refusals", func() bool { return len(ephemerals(e.fake)) == 3 })
	if st := e.svc.Request(r.ID).Status; st != jit.StatusPending {
		t.Fatalf("status = %s, want pending", st)
	}
	all := strings.Join(ephemerals(e.fake), "\n")
	for _, want := range []string{"UGONE: :no_entry: You can't act on this request from Slack: gone@example.com has no device on the tailnet",
		"UNOTCONF: :no_entry: You can't act on this request from Slack: your Slack email address is not confirmed",
		"UOTHER: :no_entry: You can't act on this request from Slack: your Slack account belongs to another workspace"} {
		if !strings.Contains(all, want) {
			t.Errorf("refusals lack %q:\n%s", want, all)
		}
	}

	// Sam is on the tailnet: he approves, and the record says which Slack
	// account did it.
	e.fake.Send(slack.Interactive("USAM", "C0SREONCALL", ts, actionApprove, r.ID))
	waitFor(t, "approved", func() bool { return e.svc.Request(r.ID).Status == jit.StatusApproved })
	if a := e.svc.Request(r.ID).Approvals[0]; a.Login != "sam@example.com" || a.SlackUser != "T0FAKE/USAM" {
		t.Errorf("approval = %+v", a)
	}
}

// "Decide in the browser only" holds for a decline form that was opened
// before the setting changed: the service refuses Slack decisions itself.
func TestBrowserOnlyRefusesOpenDeclineForm(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	r := e.submit(t, maya)
	w := *e.flow
	w.Slack = &jit.WorkflowSlack{Channel: "C0SREONCALL", BrowserOnly: true}
	if _, err := e.svc.UpdateWorkflow(w.ID, w); err != nil {
		t.Fatal(err)
	}
	// The submission's view is V1 in the fake: the form opened earlier.
	e.fake.OpenView(context.Background(), "t", notice("Decline request", "…"))
	e.fake.Send(slack.Submission("UPRIYA", declineView, r.ID, map[string]map[string]string{reasonBlock: {reasonInput: "no"}}))
	waitFor(t, "the refusal", func() bool {
		b, _ := json.Marshal(e.fake.OpenedViews()[0])
		return strings.Contains(string(b), "decided in the browser only")
	})
	if st := e.svc.Request(r.ID).Status; st != jit.StatusPending {
		t.Fatalf("status = %s, want pending", st)
	}
	// The browser still works for the same person.
	if _, err := e.svc.Decline(context.Background(), jit.Identity{Login: "priya@example.com", DeviceID: "nPRIYA"}, r.ID, "no"); err != nil {
		t.Fatal(err)
	}
}

// A request that can't be posted to its flow's channel is flagged in the
// sidebar and on the request page, not only in the log.
func TestPostFailureIsShown(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0GONE0000"})
	r := e.submit(t, maya)
	waitFor(t, "the failure noted", func() bool { return e.bot.Problem() != "" })
	if p := e.bot.Problem(); !strings.Contains(p, "can't be posted to its Slack channel") || !strings.Contains(p, "Kubernetes (read-only)") {
		t.Errorf("problem = %q", p)
	}
	if n := e.bot.RequestNote(e.svc.Request(r.ID)); !strings.Contains(n, "Not posted to Slack") {
		t.Errorf("note = %q", n)
	}
	// Fixing the channel clears it on the next post.
	w := *e.flow
	w.Slack = &jit.WorkflowSlack{Channel: "C0SREONCALL"}
	if _, err := e.svc.UpdateWorkflow(w.ID, w); err != nil {
		t.Fatal(err)
	}
	e.bot.reconcile(context.Background())
	if p := e.bot.Problem(); p != "" {
		t.Errorf("problem after the fix = %q", p)
	}
}
