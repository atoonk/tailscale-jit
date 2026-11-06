package jithttp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
	"github.com/atoonk/tailscale-jit/jitd/internal/slackbot"
)

func TestSlackPageAndAPI(t *testing.T) {
	f := slack.NewFake()
	f.AddChannel("C0SREONCALL", "sre-oncall", false)
	f.AddUser("UBOB", "bob@example.com", "Bob")
	var bot *slackbot.Bot
	srv, _, h := newTestServerWith(t, func(s *Server) {
		bot = &slackbot.Bot{Svc: s.Svc, Log: s.Log, BaseURL: s.BaseURL, EnvFile: filepath.Join(t.TempDir(), "env"),
			NewAPI: func(string, string) slack.API { return f }, Dial: f.Dial}
		s.Svc.Notify = bot
		s.Slack = bot
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bot.Start(ctx)
	_ = h

	// Not connected: the page walks through setup; non-admins are kept out.
	for _, tc := range []struct {
		user, path string
		status     int
		want       []string
	}{
		{"root", "/admin/slack", 200, []string{"Connect Slack", "Create the Slack app", "manifest_json", `value="example.com"`, "SLACK_BOT_TOKEN"}},
		{"alice", "/admin/slack", 403, []string{"Admins only"}},
		{"root", "/admin/workflows/new", 200, []string{`name="slack_channel"`, "Connect Slack on the"}},
		{"root", "/", 200, []string{`href="/admin/slack"`}},
	} {
		status, body := getPage(t, srv, tc.user, tc.path)
		if status != tc.status {
			t.Errorf("%s as %s: status %d", tc.path, tc.user, status)
		}
		for _, w := range tc.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s as %s: missing %q", tc.path, tc.user, w)
			}
		}
	}
	if code := call(t, srv, "alice", "GET", "/v1/slack", nil, nil); code != 403 {
		t.Errorf("GET /v1/slack as alice: %d", code)
	}

	// Bad tokens are refused with a hint; good ones connect.
	var e apiErr
	if code := call(t, srv, "root", "POST", "/v1/slack/connect", map[string]any{"bot_token": "xoxp-user", "app_token": "xapp-1", "allowed_domains": []string{"example.com"}}, &e); code != 400 || !strings.Contains(e.Error.Message, "xoxb-") {
		t.Errorf("user token accepted: %d %+v", code, e)
	}
	var st slackbot.Status
	if code := call(t, srv, "root", "POST", "/v1/slack/connect", map[string]any{"bot_token": "xoxb-secret-9999", "app_token": "xapp-secret-8888", "allowed_domains": []string{"Example.com"}}, &st); code != 200 {
		t.Fatalf("connect: %d", code)
	}
	if st.AllowedDomains[0] != "example.com" || st.BotTokenHint != "…9999" {
		t.Errorf("status = %+v", st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !bot.Status().Connected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// A flow with a channel, set through the API as the form does.
	var wf jit.Workflow
	if code := call(t, srv, "root", "POST", "/v1/workflows", map[string]any{
		"name": "RDP flow", "attribute": "windows_rdp", "requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"},
		"slack": map[string]any{"channel": "C0SREONCALL", "channel_name": "sre-oncall", "dm_approvers": true},
	}, &wf); code != 201 || wf.Slack == nil || wf.Slack.Channel != "C0SREONCALL" {
		t.Fatalf("create with slack: %d %+v", code, wf.Slack)
	}
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"/admin/slack", []string{"Example Corp", "connected", "RDP flow", "#sre-oncall", "bob@example.com", "→ @bob", "Send a test message", "Disconnect"}},
		{"/admin/workflows/" + wf.ID, []string{`value="C0SREONCALL" data-name="sre-oncall" selected`, `name="slack_dm" checked`}},
		{"/admin/workflows", []string{"Slack: #sre-oncall"}},
	} {
		_, body := getPage(t, srv, "root", tc.path)
		for _, w := range tc.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", tc.path, w)
			}
		}
	}
	// The tokens appear nowhere.
	for _, path := range []string{"/admin/slack", "/v1/slack", "/api/openapi.json"} {
		_, body := getPage(t, srv, "root", path)
		if strings.Contains(body, "secret-9999") || strings.Contains(body, "secret-8888") {
			t.Errorf("%s shows a token", path)
		}
	}

	// A request is posted; approving from Slack shows "via Slack" on its page.
	var r jit.AccessRequest
	call(t, srv, "alice", "POST", "/v1/requests", map[string]any{"workflow_id": wf.ID, "reason": "patch tuesday"}, &r)
	for time.Now().Before(deadline) && len(f.PostsTo("C0SREONCALL")) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	posts := f.PostsTo("C0SREONCALL")
	if len(posts) != 1 {
		t.Fatalf("posts = %d", len(posts))
	}
	f.Send(slack.Interactive("UBOB", "C0SREONCALL", posts[0].TS, "jit_approve", r.ID))
	for time.Now().Before(deadline) && h.Svc.Request(r.ID).Status != jit.StatusApproved {
		time.Sleep(10 * time.Millisecond)
	}
	if _, body := getPage(t, srv, "alice", "/requests/"+r.ID); !strings.Contains(body, "via Slack") {
		t.Errorf("request page does not say via Slack: status %s, ephemeral %+v", h.Svc.Request(r.ID).Status, f.EphemeralPosts())
	}

	if code := call(t, srv, "root", "POST", "/v1/slack/test", map[string]any{"channel": "C0SREONCALL"}, nil); code != 200 {
		t.Errorf("test message: %d", code)
	}
	if code := call(t, srv, "root", "POST", "/v1/slack/disconnect", nil, &st); code != 200 || st.Configured() {
		t.Errorf("disconnect: %d %+v", code, st)
	}
}
