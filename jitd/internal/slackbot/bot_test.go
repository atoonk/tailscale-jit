package slackbot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// fakeTS is the Tailscale API for these tests. Sam, Maya and Priya are on
// the tailnet (they own devices); policyErr makes the policy unreadable.
type fakeTS struct{ policyErr error }

func (fakeTS) SetAttribute(context.Context, string, string, any, time.Time, string) error { return nil }
func (fakeTS) GetAttributes(context.Context, string) (tsapi.Attributes, error) {
	return tsapi.Attributes{Attributes: map[string]any{}}, nil
}
func (fakeTS) DeleteAttribute(context.Context, string, string) error { return nil }
func (fakeTS) ListDevices(context.Context) ([]tsapi.Device, error) {
	return []tsapi.Device{
		{NodeID: "nSAMOLD", Name: "sam-old.ts.net", User: "sam@example.com", Authorized: true, LastSeen: time.Now().Add(-48 * time.Hour)},
		{NodeID: "nSAM", Name: "sam-mac.ts.net", User: "sam@example.com", OS: "macOS", Authorized: true, LastSeen: time.Now()},
		{NodeID: "nSAMTAG", Name: "sam-server.ts.net", User: "sam@example.com", Tags: []string{"tag:server"}, Authorized: true},
		{NodeID: "nMAYA", Name: "maya-mac.ts.net", User: "maya@example.com", Authorized: true},
		{NodeID: "nPRIYA", Name: "priya-pc.ts.net", User: "priya@example.com", Authorized: true},
	}, nil
}
func (f fakeTS) GetPolicy(context.Context) (tsapi.Policy, error) {
	if f.policyErr != nil {
		return tsapi.Policy{}, f.policyErr
	}
	return tsapi.Policy{Groups: map[string][]string{"group:sre": {"sam@example.com", "priya@example.com"}}}, nil
}

var (
	maya  = jit.Identity{Login: "maya@example.com", DisplayName: "Maya Chen", DeviceID: "nMAYA", DeviceName: "maya-mac"}
	agent = jit.Identity{Login: "tagged-devices", DeviceID: "nAGENT", DeviceName: "sre-agent-1", Tags: []string{"tag:sre-agent"}}
	leo   = jit.Identity{Login: "leo@example.com"}
)

type env struct {
	bot  *Bot
	svc  *jit.Service
	fake *slack.Fake
	flow *jit.Workflow
}

func newEnv(t *testing.T, flowSlack *jit.WorkflowSlack) *env {
	t.Helper()
	return newEnvTS(t, flowSlack, fakeTS{})
}

func newEnvTS(t *testing.T, flowSlack *jit.WorkflowSlack, ts fakeTS) *env {
	t.Helper()
	st, err := jit.Open(filepath.Join(t.TempDir(), "jit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &jit.Service{Store: st, TS: ts, Log: log, Admins: []jit.Principal{"leo@example.com"}}
	svc.PolicyCache = &jit.PolicyCache{TS: ts, TTL: time.Minute, Log: log}
	f := slack.NewFake()
	f.AddUser("USAM", "sam@example.com", "Sam Rivera")
	f.AddUser("UPRIYA", "Priya@Example.com", "Priya Natarajan")
	f.AddUser("UMAYA", "maya@example.com", "Maya Chen")
	f.AddUser("UOUT", "mallory@elsewhere.org", "Mallory")
	f.AddChannel("C0SREONCALL", "sre-oncall", false)
	b := &Bot{Svc: svc, Log: log, BaseURL: "http://jit", EnvFile: filepath.Join(t.TempDir(), "env"),
		NewAPI: func(string, string) slack.API { return f }, Dial: f.Dial}
	svc.Notify = b
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b.Start(ctx)
	if _, err := b.Connect(ctx, leo, ConnectInput{BotToken: "xoxb-test-1234", AppToken: "xapp-test-5678", AllowedDomains: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "socket connected", func() bool { return b.Status().Connected() })
	w, err := svc.CreateWorkflow(jit.Workflow{
		Name: "Kubernetes (read-only)", Attribute: "k8s_ro",
		Resources:  []jit.Resource{{Name: "svc:kubernetes-prod-cluster"}},
		Requesters: []jit.Principal{"autogroup:member", "tag:sre-agent"}, Approvers: []jit.Principal{"group:sre"},
		MaxDuration: jit.Duration(time.Hour), Slack: flowSlack,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{bot: b, svc: svc, fake: f, flow: w}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) submit(t *testing.T, who jit.Identity) *jit.AccessRequest {
	t.Helper()
	r, err := e.svc.Submit(context.Background(), who, jit.NewRequest{WorkflowID: e.flow.ID, Duration: jit.Duration(30 * time.Minute), Reason: "checkout p99 is 4.8s; read pods and logs"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func blocksJSON(m slack.Message) string {
	b, _ := json.Marshal(m.Blocks)
	return string(b)
}

func lastPost(t *testing.T, f *slack.Fake, channel string) slack.Post {
	t.Helper()
	ps := f.PostsTo(channel)
	if len(ps) == 0 {
		t.Fatalf("nothing posted to %s", channel)
	}
	return ps[len(ps)-1]
}

func TestPostThenApproveFromSlack(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL", ChannelName: "sre-oncall"})
	r := e.submit(t, agent)
	waitFor(t, "the request posted", func() bool { return len(e.fake.PostsTo("C0SREONCALL")) == 1 })
	p := lastPost(t, e.fake, "C0SREONCALL")
	js := blocksJSON(p.Message)
	for _, want := range []string{"Kubernetes (read-only)", "jit_approve", "jit_decline", "http://jit/requests/" + r.ID, "svc:kubernetes-prod-cluster", "checkout p99"} {
		if !strings.Contains(js, want) {
			t.Errorf("message lacks %q: %s", want, js)
		}
	}
	waitFor(t, "the message recorded", func() bool { return len(e.svc.Request(r.ID).Slack) == 1 })

	// Sam (group:sre, by email) approves from the channel.
	if err := e.fake.Send(slack.Interactive("USAM", "C0SREONCALL", p.TS, actionApprove, r.ID)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "approved", func() bool { return e.svc.Request(r.ID).Status == jit.StatusApproved })
	got := e.svc.Request(r.ID)
	if a := got.Approvals[0]; a.Login != "sam@example.com" || a.Via != jit.ViaSlack {
		t.Errorf("approval = %+v, want sam via slack", a)
	}
	if ev := got.Timeline[len(got.Timeline)-1]; ev.Type != "approved" || ev.Via != jit.ViaSlack {
		t.Errorf("last event = %+v", ev)
	}
	// The message loses its buttons and says who approved.
	waitFor(t, "the message updated", func() bool {
		js := blocksJSON(lastPost(t, e.fake, "C0SREONCALL").Message)
		return !strings.Contains(js, "jit_approve") && strings.Contains(js, "Approved by *sam@example.com* via Slack")
	})
}

func TestStrangersCannotApprove(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	r := e.submit(t, agent)
	waitFor(t, "posted", func() bool { return len(e.fake.PostsTo("C0SREONCALL")) == 1 })
	ts := lastPost(t, e.fake, "C0SREONCALL").TS
	// Maya is a member but no approver; Mallory's email is outside the
	// allowed domains; a guest is never matched.
	e.fake.AddUser("UGUEST", "guest@example.com", "Guest")
	e.fake.MakeGuest("UGUEST")
	for _, u := range []string{"UMAYA", "UOUT", "UGUEST", "UNOBODY"} {
		e.fake.Send(slack.Interactive(u, "C0SREONCALL", ts, actionApprove, r.ID))
	}
	waitFor(t, "four refusals", func() bool { return len(ephemerals(e.fake)) == 4 })
	if st := e.svc.Request(r.ID).Status; st != jit.StatusPending {
		t.Fatalf("status = %s, want pending", st)
	}
	all := strings.Join(ephemerals(e.fake), "\n")
	for _, want := range []string{"isn't an approver", "not in a domain allowed", "guest accounts"} {
		if !strings.Contains(all, want) {
			t.Errorf("refusals lack %q:\n%s", want, all)
		}
	}
}

func ephemerals(f *slack.Fake) []string {
	var out []string
	for _, p := range f.EphemeralPosts() {
		out = append(out, p.User+": "+p.Message.Text)
	}
	return out
}

func TestDeclineThroughModal(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	r := e.submit(t, maya)
	waitFor(t, "posted", func() bool { return len(e.fake.PostsTo("C0SREONCALL")) == 1 })
	ts := lastPost(t, e.fake, "C0SREONCALL").TS
	e.fake.Send(slack.Interactive("UPRIYA", "C0SREONCALL", ts, actionDecline, r.ID))
	// The form opens at once ("Checking…") and fills in once Priya is known.
	waitFor(t, "the decline form", func() bool {
		vs := e.fake.OpenedViews()
		return len(vs) == 1 && vs[0].CallbackID == declineView
	})
	if v := e.fake.OpenedViews()[0]; v.PrivateMetadata != r.ID {
		t.Fatalf("view = %+v", v)
	}
	// An empty reason keeps the form open with an error.
	acks := e.fake.Acks()
	e.fake.Send(slack.Submission("UPRIYA", declineView, r.ID, map[string]map[string]string{reasonBlock: {reasonInput: " "}}))
	ack := readAck(t, acks, "env-view-"+r.ID)
	if !strings.Contains(ack, "A reason is required") {
		t.Fatalf("ack = %s", ack)
	}
	e.fake.Send(slack.Submission("UPRIYA", declineView, r.ID, map[string]map[string]string{reasonBlock: {reasonInput: "use the read replica"}}))
	// The ack only says "Declining…"; the decline runs after it.
	ack = readAck(t, acks, "env-view-"+r.ID)
	if !strings.Contains(ack, "Declining") {
		t.Fatalf("ack = %s", ack)
	}
	waitFor(t, "declined", func() bool { return e.svc.Request(r.ID).Status == jit.StatusDeclined })
	waitFor(t, "the outcome in the form", func() bool {
		b, _ := json.Marshal(e.fake.OpenedViews()[0])
		return strings.Contains(string(b), "You declined")
	})
	got := e.svc.Request(r.ID)
	ev := got.Timeline[len(got.Timeline)-1]
	if got.Status != jit.StatusDeclined || ev.Actor != "priya@example.com" || ev.Via != jit.ViaSlack || ev.SlackUser != "T0FAKE/UPRIYA" || ev.Note != "use the read replica" {
		t.Fatalf("request = %s, last event %+v", got.Status, ev)
	}
	waitFor(t, "the message updated", func() bool {
		return strings.Contains(blocksJSON(lastPost(t, e.fake, "C0SREONCALL").Message), "use the read replica")
	})
}

func readAck(t *testing.T, acks <-chan []byte, envID string) string {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case b := <-acks:
			if strings.Contains(string(b), envID) {
				return string(b)
			}
		case <-timeout:
			t.Fatalf("no ack for %s", envID)
		}
	}
}

func TestDMsAndBrowserOnly(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{DMApprovers: true, BrowserOnly: true})
	r := e.submit(t, maya)
	waitFor(t, "DMs to both SREs", func() bool { return len(e.svc.Request(r.ID).Slack) == 2 })
	for _, m := range e.svc.Request(r.ID).Slack {
		if m.Kind != "dm" || (m.User != "USAM" && m.User != "UPRIYA") {
			t.Errorf("message %+v", m)
		}
		js := blocksJSON(lastPost(t, e.fake, m.Channel).Message)
		if strings.Contains(js, "jit_approve") || !strings.Contains(js, "browser only") {
			t.Errorf("browser-only flow got buttons: %s", js)
		}
	}
	// A button on a stale message is refused, not acted on.
	m := e.svc.Request(r.ID).Slack[0]
	e.fake.Send(slack.Interactive(m.User, m.Channel, m.TS, actionApprove, r.ID))
	waitFor(t, "refusal", func() bool { return len(ephemerals(e.fake)) == 1 })
	if st := e.svc.Request(r.ID).Status; st != jit.StatusPending {
		t.Fatalf("status = %s", st)
	}
}

func TestReconcileAfterOutage(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	// Slack refuses posts for a while: the request is filed regardless.
	e.fake.SetFail("chat.postMessage", "service_unavailable")
	r := e.submit(t, agent)
	time.Sleep(100 * time.Millisecond)
	if n := len(e.fake.PostsTo("C0SREONCALL")); n != 0 {
		t.Fatalf("posted %d", n)
	}
	e.fake.SetFail("chat.postMessage", "")
	e.bot.reconcile(context.Background())
	if n := len(e.fake.PostsTo("C0SREONCALL")); n != 1 {
		t.Fatalf("after reconcile: %d posts", n)
	}
	// Reconciling again posts nothing new.
	e.bot.reconcile(context.Background())
	if n := len(e.fake.PostsTo("C0SREONCALL")); n != 1 {
		t.Fatalf("second reconcile: %d posts", n)
	}
	_ = r
}

func TestCommandSummary(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	e.submit(t, agent)
	acks := e.fake.Acks()
	e.fake.Send(slack.Command("USAM", "C0SREONCALL", "/jit", ""))
	// The ack goes out at once and empty; the answer follows through the
	// command's response_url.
	if ack := readAck(t, acks, "env-cmd-"); strings.Contains(ack, "payload") {
		t.Errorf("ack carries a reply: %s", ack)
	}
	waitFor(t, "the /jit answer", func() bool { return len(e.fake.RepliesTo(slack.CommandResponseURL(""))) == 1 })
	reply := blocksJSON(e.fake.RepliesTo(slack.CommandResponseURL(""))[0])
	for _, want := range []string{"sam@example.com", "Waiting for your approval (1)", "Kubernetes (read-only)", actionRequestForm, "/jit help"} {
		if !strings.Contains(reply, want) {
			t.Errorf("reply lacks %q: %s", want, reply)
		}
	}
	e.fake.Send(slack.Command("USAM", "C0SREONCALL", "/jit", "help"))
	if ack := readAck(t, acks, "env-cmd-help"); !strings.Contains(ack, actionRequestForm) || strings.Contains(ack, "Waiting for") {
		t.Errorf("help: %s", ack)
	}
	e.fake.Send(slack.Command("USAM", "C0SREONCALL", "/jit", "frobnicate"))
	if ack := readAck(t, acks, "env-cmd-frobnicate"); !strings.Contains(ack, "isn't a JIT access command") {
		t.Errorf("unknown: %s", ack)
	}
	// The Request button opens the request form.
	e.fake.Send(slack.Interactive("USAM", "C0SREONCALL", "9.9", actionRequestForm, ""))
	waitFor(t, "form from the button", func() bool {
		vs := e.fake.OpenedViews()
		return len(vs) == 1 && vs[0].CallbackID == requestView
	})
}

func TestRequestFromSlack(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	acks := e.fake.Acks()
	e.fake.Send(slack.Command("USAM", "C0SREONCALL", "/jit", "request"))
	if ack := readAck(t, acks, "env-cmd-request"); strings.Contains(ack, "ephemeral") {
		t.Fatalf("form not opened: %s", ack)
	}
	// The form opens at once and fills in when the devices are known.
	view := func() string {
		vs := e.fake.OpenedViews()
		if len(vs) == 0 {
			return ""
		}
		b, _ := json.Marshal(vs[0])
		return string(b)
	}
	waitFor(t, "form filled", func() bool { return strings.Contains(view(), `"callback_id":"`+requestView+`"`) })
	// Only sam's own untagged devices, the most recent first.
	if s := view(); !strings.Contains(s, "nSAM\"") || strings.Contains(s, "nSAMTAG") || strings.Contains(s, "nMAYA") ||
		strings.Index(s, "nSAM\"") > strings.Index(s, "nSAMOLD") {
		t.Fatalf("device choices: %s", s)
	}

	n := 0
	submit := func(device, dur string) (ack, outcome string) {
		n++
		env := slack.Submission("USAM", requestView, "", map[string]map[string]string{
			flowBlock: {flowBlock: e.flow.ID}, deviceBlock: {deviceBlock: device},
			durationBlock: {durationBlock: dur}, reasonBlock: {reasonInput: "check the rollout"},
		})
		env.EnvelopeID += fmt.Sprint(n)
		// Slack shows the ack's "Filing" view; the fake does not, so set it.
		e.fake.UpdateView(context.Background(), "V1", notice("Request access", "Filing your request…"))
		e.fake.Send(env)
		ack = readAck(t, acks, env.EnvelopeID)
		if !strings.Contains(ack, "Filing your request") {
			return ack, ""
		}
		waitFor(t, "outcome", func() bool { return !strings.Contains(view(), "Filing your request") })
		return ack, view()
	}
	// Over the flow's maximum: the form stays open with an error.
	if ack, _ := submit("nSAM", "1d"); !strings.Contains(ack, `"duration":"This flow allows up to 1 hour`) {
		t.Fatalf("over the max: %s", ack)
	}
	// Someone else's device, and a tagged one, are refused.
	for _, dev := range []string{"nMAYA", "nSAMTAG"} {
		if _, out := submit(dev, ""); !strings.Contains(out, "not one of yours") {
			t.Fatalf("%s: %s", dev, out)
		}
	}
	if _, out := submit("nSAM", "30m"); !strings.Contains(out, "Request filed") {
		t.Fatalf("submit: %s", out)
	}
	rs := e.svc.ListRequests(context.Background(), jit.ListFilter{Viewer: leo, Scope: jit.ScopeAll})
	if len(rs) != 1 || rs[0].TargetDeviceID != "nSAM" || rs[0].Requester.Via != jit.ViaSlack || rs[0].Duration != jit.Duration(30*time.Minute) {
		t.Fatalf("requests = %+v", rs)
	}
	waitFor(t, "posted", func() bool { return len(e.fake.PostsTo("C0SREONCALL")) == 1 })
	// A second one for the same device points at the first.
	if _, out := submit("nSAM", "15m"); !strings.Contains(out, rs[0].ID) {
		t.Fatalf("duplicate: %s", out)
	}

	// Outsiders get a form that says why they can't request.
	e.fake.Send(slack.Command("UOUT", "C0SREONCALL", "/jit", "request "))
	readAck(t, acks, "env-cmd-request ")
	waitFor(t, "outsider notice", func() bool {
		vs := e.fake.OpenedViews()
		b, _ := json.Marshal(vs[len(vs)-1])
		return strings.Contains(string(b), "can't tell who you are")
	})
}

func TestTokensNeverShownAndEnvWins(t *testing.T) {
	e := newEnv(t, nil)
	st, _ := json.Marshal(e.bot.Status())
	if strings.Contains(string(st), "xoxb-test") || strings.Contains(string(st), "xapp-test") {
		t.Fatalf("status shows a token: %s", st)
	}
	if !strings.Contains(string(st), "…1234") {
		t.Errorf("status lacks the token hint: %s", st)
	}
	// Tokens in the env file take over, and the page can't change them.
	os.WriteFile(e.bot.EnvFile, []byte("SLACK_BOT_TOKEN=xoxb-env-aaaa\nSLACK_APP_TOKEN=xapp-env-bbbb\n"), 0o600)
	if err := e.bot.load(); err != nil {
		t.Fatal(err)
	}
	if s := e.bot.Status(); s.Source != "env" || s.BotTokenHint != "…aaaa" {
		t.Fatalf("status = %+v", s)
	}
	if _, err := e.bot.Connect(context.Background(), leo, ConnectInput{BotToken: "xoxb-x-1111", AppToken: "xapp-x-2222", AllowedDomains: []string{"example.com"}}); err == nil {
		t.Fatal("connect over env settings succeeded")
	}
}

func TestDisconnectRevokes(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	if err := e.bot.Disconnect(context.Background(), leo); err != nil {
		t.Fatal(err)
	}
	if !e.fake.IsRevoked() {
		t.Error("bot token not revoked")
	}
	if e.bot.Status().Configured() {
		t.Error("still configured")
	}
	var s Settings
	if ok, _ := e.svc.Store.GetSetting(settingKey, &s); ok {
		t.Error("settings still stored")
	}
	// With Slack gone, filing still works and nothing is posted.
	e.submit(t, agent)
	time.Sleep(50 * time.Millisecond)
	if n := len(e.fake.PostsTo("C0SREONCALL")); n != 0 {
		t.Errorf("posted %d after disconnect", n)
	}
}

func TestCheckApprovers(t *testing.T) {
	e := newEnv(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"})
	if _, err := e.svc.CreateWorkflow(jit.Workflow{Name: "SSH", Attribute: "ssh", Requesters: []jit.Principal{"autogroup:member"},
		Approvers: []jit.Principal{"lee@example.com", "tag:approver-bot", "sam@example.com"}, Slack: &jit.WorkflowSlack{Channel: "C0GONE0000"}}); err != nil {
		t.Fatal(err)
	}
	fcs, err := e.bot.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(fcs)
	for _, want := range []string{`"slack_user":"@sam"`, `"login":"lee@example.com","problem":"no Slack account with this email"`, `"other_approvers":["tag:approver-bot"]`, `"channel_issue":"Slack can't find that channel`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("check lacks %s:\n%s", want, got)
		}
	}
}

func TestCheckShowsUnreadableGroups(t *testing.T) {
	// An unreadable policy file leaves group approvers out; the check says so
	// instead of showing a flow with nobody to match.
	e := newEnvTS(t, &jit.WorkflowSlack{Channel: "C0SREONCALL"}, fakeTS{policyErr: errors.New("403 forbidden")})
	fcs, err := e.bot.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(fcs)
	if !strings.Contains(string(got), `"approver_issue":"group approvers left out`) {
		t.Errorf("check hides the group failure:\n%s", got)
	}
}

func TestRenderEscapes(t *testing.T) {
	r := &jit.AccessRequest{ID: "req_1", WorkflowName: "DB <b>", Requester: jit.Identity{Login: "x@example.com"}, Duration: jit.Duration(time.Hour),
		Reason: "<!here> & <@U1> fix it", Status: jit.StatusPending, ApprovalsRequired: 1, CreatedAt: time.Unix(1700000000, 0)}
	js := blocksJSON(render(renderInput{R: r, URL: "http://jit/requests/req_1", Buttons: true}))
	if strings.Contains(js, "<!here>") || strings.Contains(js, "<@U1>") || strings.Contains(js, "DB <b>") {
		t.Fatalf("unescaped text: %s", js)
	}
}

func TestManifest(t *testing.T) {
	u := ManifestURL()
	if !strings.HasPrefix(u, "https://api.slack.com/apps?new_app=1&manifest_json=") {
		t.Fatal(u)
	}
	b, _ := json.Marshal(Manifest())
	for _, want := range []string{`"socket_mode_enabled":true`, `"command":"/jit"`, `"users:read.email"`, `"is_enabled":true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("manifest lacks %s", want)
		}
	}
}
