package slackbot

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

func (e *env) makeAutomatic(t *testing.T) {
	t.Helper()
	fl := *e.flow
	fl.AutoApprove, fl.Approvers = true, nil
	w, err := e.svc.UpdateWorkflow(e.flow.ID, fl)
	if err != nil {
		t.Fatal(err)
	}
	e.flow = w
}

// An automatic flow asks nobody: the channel gets one message once the
// access is granted, and never a card with Approve and Decline.
func TestAutomaticGrantIsPostedOnce(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL", DMApprovers: true})
	e.makeAutomatic(t)
	r := e.submit(t, maya)
	if r.Status != jit.StatusApproved {
		t.Fatalf("status = %s", r.Status)
	}
	waitFor(t, "the grant in the channel", func() bool { return len(e.fake.PostsTo("C0SREONCALL")) == 1 })
	time.Sleep(100 * time.Millisecond)
	e.bot.reconcile(context.Background())
	posts := e.fake.PostsTo("C0SREONCALL")
	if len(posts) != 1 {
		t.Fatalf("channel posts = %d, want 1", len(posts))
	}
	for _, p := range posts {
		if b := blocksJSON(p.Message); strings.Contains(b, actionApprove) || strings.Contains(b, actionDecline) {
			t.Errorf("an automatic grant was posted with buttons: %s", b)
		}
	}
	if b := blocksJSON(posts[0].Message); !strings.Contains(b, "automatic") {
		t.Errorf("the message does not say the approval was automatic: %s", b)
	}
	for _, m := range e.svc.Request(r.ID).Slack {
		if m.Kind == "dm" {
			t.Errorf("an approver was sent a direct message about a request nobody decides: %+v", m)
		}
	}
}

// The worker did not see the request (Slack was reconnecting, the queue was
// full): the catch-up still posts the grant.
func TestAutomaticGrantIsPostedByCatchUp(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	e.makeAutomatic(t)
	e.svc.Notify = nil
	r := e.submit(t, maya)
	if r.Status != jit.StatusApproved {
		t.Fatalf("status = %s", r.Status)
	}
	e.svc.Notify = e.bot
	e.bot.reconcile(context.Background())
	e.bot.reconcile(context.Background())
	if n := len(e.fake.PostsTo("C0SREONCALL")); n != 1 {
		t.Errorf("channel posts about an automatic grant = %d, want 1", n)
	}
}

// A request scheduled ahead on an automatic flow is approved when it is
// filed. The channel hears about it then, not only when the access starts.
func TestAutomaticScheduledGrantIsPostedOnce(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	e.makeAutomatic(t)
	start := time.Now().Add(time.Hour)
	r, err := e.svc.Submit(context.Background(), maya, jit.NewRequest{WorkflowID: e.flow.ID, Duration: jit.Duration(30 * time.Minute), Reason: "maintenance window", StartAt: &start})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != jit.StatusScheduled {
		t.Fatalf("status = %s", r.Status)
	}
	waitFor(t, "the scheduled grant in the channel", func() bool { return len(e.fake.PostsTo("C0SREONCALL")) == 1 })
	time.Sleep(100 * time.Millisecond)
	e.bot.reconcile(context.Background())
	posts := e.fake.PostsTo("C0SREONCALL")
	if len(posts) != 1 {
		t.Fatalf("channel posts = %d, want 1", len(posts))
	}
	b := blocksJSON(posts[0].Message)
	if strings.Contains(b, actionApprove) || strings.Contains(b, actionDecline) {
		t.Errorf("an automatic grant was posted with buttons: %s", b)
	}
	if !strings.Contains(b, "automatic") || !strings.Contains(b, "starts") {
		t.Errorf("the message does not say the approval was automatic and when it starts: %s", b)
	}
}
