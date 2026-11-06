package slackbot

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
)

// Bot is the Slack integration. It is safe to use before Start and while
// Slack is not set up: it then does nothing.
type Bot struct {
	Svc     *jit.Service
	Log     *slog.Logger
	BaseURL string // e.g. http://jit; request links point here
	// EnvFile is jitd's env file; SLACK_BOT_TOKEN and SLACK_APP_TOKEN in it
	// (or in the environment) take the place of tokens saved on the page.
	EnvFile string
	// NewAPI makes the Slack client for a pair of tokens; slack.New if nil.
	NewAPI func(botToken, appToken string) slack.API
	// Dial opens the Socket Mode connection; slack.DialWebSocket if nil.
	Dial slack.Dialer
	Now  func() time.Time

	// applyMu serialises apply, so two connects can't interleave. It is
	// held while the old socket stops; mu is not (see apply).
	applyMu sync.Mutex

	mu       sync.Mutex
	parent   context.Context
	settings Settings
	source   string // "ui", "env" or ""
	api      slack.API
	sock     *slack.Socket
	stopSock context.CancelFunc
	sockDone chan struct{}

	// queue and kick are made once (init) and never change, so
	// RequestChanged, which jit.Service calls with its lock held, needs no
	// lock of the bot's.
	initOnce sync.Once
	queue    chan string // request IDs whose messages need a look
	kick     chan struct{}

	ids identities

	rmu      sync.Mutex
	rendered map[string]string // request ID -> digest of the message last sent

	cmu       sync.Mutex
	channels  []slack.Channel
	channelAt time.Time

	// postFailed holds, per approval flow, why its last channel post failed;
	// a success clears it. It feeds the sidebar warning and the request page.
	pmu        sync.Mutex
	postFailed map[string]string
}

// MaxDMs caps the direct messages sent for one request.
const MaxDMs = 25

// reconcileEvery is how often the bot catches up on what it missed (jitd or
// Slack was down when a request was filed, a message update failed).
const reconcileEvery = 10 * time.Minute

func (b *Bot) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Bot) log() *slog.Logger {
	if b.Log == nil {
		return slog.Default()
	}
	return b.Log
}

func (b *Bot) newAPI(bot, app string) slack.API {
	if b.NewAPI != nil {
		return b.NewAPI(bot, app)
	}
	return slack.New(bot, app)
}

func (b *Bot) init() {
	b.initOnce.Do(func() {
		b.queue = make(chan string, 512)
		b.kick = make(chan struct{}, 1)
	})
}

// Start loads the connection and keeps it until ctx ends.
func (b *Bot) Start(ctx context.Context) {
	b.init()
	b.mu.Lock()
	b.parent = ctx
	b.mu.Unlock()

	if err := b.load(); err != nil {
		b.log().Error("slack: reading settings", "err", err)
	}
	go b.worker(ctx)
}

// load reads the settings (the env file wins over the page) and connects if
// there are tokens.
func (b *Bot) load() error {
	env, err := envSettings(b.EnvFile)
	if err != nil {
		return err
	}
	var saved Settings
	if _, err := b.Svc.Store.GetSetting(settingKey, &saved); err != nil {
		return err
	}
	var s Settings
	source := ""
	switch {
	case env.configured():
		s, source = saved, "env"
		s.BotToken, s.AppToken = env.BotToken, env.AppToken
		if len(env.AllowedDomains) > 0 {
			s.AllowedDomains = env.AllowedDomains
		}
	case saved.configured():
		s, source = saved, "ui"
	}
	if source == "" {
		return nil
	}
	b.apply(s, source)
	return nil
}

// apply switches to new settings and (re)starts the socket.
//
// The old socket is stopped without holding b.mu: its reader may be inside a
// handler that needs b.mu (client, settingsCopy), and waiting for it while
// holding b.mu would deadlock the bot and, through RequestChanged, every
// request action.
func (b *Bot) apply(s Settings, source string) {
	b.applyMu.Lock()
	defer b.applyMu.Unlock()
	b.init()

	b.mu.Lock()
	stop, done := b.stopSock, b.sockDone
	b.api, b.sock, b.stopSock, b.sockDone = nil, nil, nil, nil
	b.settings, b.source = s, source
	parent := b.parent
	b.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}

	b.ids.reset()
	b.rmu.Lock()
	b.rendered = nil
	b.rmu.Unlock()
	b.cmu.Lock()
	b.channels = nil
	b.cmu.Unlock()
	b.pmu.Lock()
	b.postFailed = nil
	b.pmu.Unlock()
	if !s.configured() || parent == nil {
		return
	}
	api := b.newAPI(s.BotToken, s.AppToken)
	ctx, cancel := context.WithCancel(parent)
	sock := &slack.Socket{API: api, Dial: b.Dial, Handle: b.handle,
		Logf: func(f string, a ...any) { b.log().Info(fmt.Sprintf(f, a...)) }}
	done = make(chan struct{})
	b.mu.Lock()
	b.api, b.sock, b.stopSock, b.sockDone = api, sock, cancel, done
	b.mu.Unlock()
	go func() {
		defer close(done)
		sock.Run(ctx)
	}()
	if s.TeamID == "" {
		// Set up from the env file before it was ever connected on the
		// page: learn which workspace the token is for, so users from other
		// workspaces can be told apart (see userProblem).
		go b.learnTeam(ctx, api)
	}
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// learnTeam fills in the workspace from auth.test.
func (b *Bot) learnTeam(ctx context.Context, api slack.API) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	auth, err := api.AuthTest(cctx)
	if err != nil {
		b.log().Warn("slack: auth.test", "err", err)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.api != api {
		return // replaced meanwhile
	}
	b.settings.TeamID, b.settings.TeamName, b.settings.TeamURL = auth.TeamID, auth.Team, auth.URL
	b.settings.BotUserID, b.settings.BotName = auth.UserID, auth.User
}

// client returns the Slack client, or nil when Slack is not set up.
func (b *Bot) client() slack.API {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.api
}

func (b *Bot) settingsCopy() Settings {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.settings
	s.AllowedDomains = slices.Clone(s.AllowedDomains)
	return s
}

// Status describes the connection, without the tokens.
func (b *Bot) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := Status{
		Source: b.source, EnvFile: b.EnvFile, State: "off", ManifestURL: ManifestURL(),
		TeamName: b.settings.TeamName, TeamURL: b.settings.TeamURL, BotName: b.settings.BotName,
		BotTokenHint: hint(b.settings.BotToken), AppTokenHint: hint(b.settings.AppToken),
		AllowedDomains: jit.OrEmpty(slices.Clone(b.settings.AllowedDomains)),
		ConnectedBy:    b.settings.ConnectedBy, ConnectedAt: b.settings.ConnectedAt,
	}
	if b.sock != nil {
		s := b.sock.Status()
		st.State, st.Since, st.LastError = cmp.Or(s.State, "connecting"), s.Since, s.LastError
	}
	return st
}

// Problem says what is wrong with a configured connection, for the warning
// dot in the sidebar, or "": the connection is down, or requests could not
// be posted to a flow's channel.
func (b *Bot) Problem() string {
	st := b.Status()
	if !st.Configured() {
		return ""
	}
	if st.State == "error" {
		return st.LastError
	}
	b.pmu.Lock()
	defer b.pmu.Unlock()
	ids := slices.Sorted(maps.Keys(b.postFailed))
	if len(ids) == 0 {
		return ""
	}
	name := ids[0]
	if w, err := b.Svc.GetWorkflow(ids[0]); err == nil {
		name = w.Name
	}
	return fmt.Sprintf("requests for %q can't be posted to its Slack channel: %s", name, b.postFailed[ids[0]])
}

// RequestNote says why a request is missing from its flow's Slack channel,
// for the request page, or "".
func (b *Bot) RequestNote(r *jit.AccessRequest) string {
	if r.Status != jit.StatusPending || slices.ContainsFunc(r.Slack, func(m jit.SlackMessage) bool { return m.Kind == "channel" }) {
		return ""
	}
	b.pmu.Lock()
	defer b.pmu.Unlock()
	if why := b.postFailed[r.WorkflowID]; why != "" {
		return "Not posted to Slack: " + why
	}
	return ""
}

func (b *Bot) setPostFailed(workflowID, why string) {
	b.pmu.Lock()
	defer b.pmu.Unlock()
	if why == "" {
		delete(b.postFailed, workflowID)
		return
	}
	if b.postFailed == nil {
		b.postFailed = map[string]string{}
	}
	b.postFailed[workflowID] = why
}

// ConnectInput is what an admin pastes on the Slack page.
type ConnectInput struct {
	BotToken       string   `json:"bot_token"`
	AppToken       string   `json:"app_token"`
	AllowedDomains []string `json:"allowed_domains"`
}

// Connect checks the tokens against Slack, saves them and connects. It
// replaces an earlier connection made on the page; one set from the env
// file can only be changed there.
func (b *Bot) Connect(ctx context.Context, admin jit.Identity, in ConnectInput) (Status, error) {
	if b.Status().Source == "env" {
		return Status{}, conflictf("Slack is set up in %s (%s and %s); change it there", b.EnvFile, EnvBotToken, EnvAppToken)
	}
	bot, app := strings.TrimSpace(in.BotToken), strings.TrimSpace(in.AppToken)
	switch {
	case !strings.HasPrefix(bot, "xoxb-"):
		return Status{}, badf("the bot token starts with xoxb- (Slack app → OAuth & Permissions → Bot User OAuth Token)")
	case !strings.HasPrefix(app, "xapp-"):
		return Status{}, badf("the app-level token starts with xapp- (Slack app → Basic Information → App-Level Tokens, with the connections:write scope)")
	}
	domains := CleanDomains(in.AllowedDomains)
	if err := validDomains(domains); err != nil {
		return Status{}, badf("%v", err)
	}
	api := b.newAPI(bot, app)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	auth, err := api.AuthTest(cctx)
	if err != nil {
		return Status{}, badf("Slack refused the bot token: %v", err)
	}
	if _, err := api.ConnectionsOpen(cctx); err != nil {
		hint := ""
		if c := slack.ErrorCode(err); c == "not_allowed_token_type" || c == "invalid_auth" {
			hint = " (it needs the connections:write scope)"
		} else if c == "missing_scope" {
			hint = " (give the app-level token the connections:write scope)"
		}
		return Status{}, badf("Slack refused the app-level token: %v%s. Is Socket Mode on for the app?", err, hint)
	}
	s := Settings{
		BotToken: bot, AppToken: app, AllowedDomains: domains,
		TeamID: auth.TeamID, TeamName: auth.Team, TeamURL: auth.URL, BotUserID: auth.UserID, BotName: auth.User,
		ConnectedBy: admin.Login, ConnectedAt: b.now().UTC(),
	}
	if err := b.Svc.Store.PutSetting(settingKey, s); err != nil {
		return Status{}, err
	}
	b.log().Info("slack connected", "team", auth.Team, "by", admin.Login)
	b.apply(s, "ui")
	return b.Status(), nil
}

// SetDomains changes the allowed email domains.
func (b *Bot) SetDomains(admin jit.Identity, domains []string) (Status, error) {
	domains = CleanDomains(domains)
	if err := validDomains(domains); err != nil {
		return Status{}, badf("%v", err)
	}
	st := b.Status()
	if !st.Configured() {
		return Status{}, conflictf("Slack is not connected")
	}
	var saved Settings
	if _, err := b.Svc.Store.GetSetting(settingKey, &saved); err != nil {
		return Status{}, err
	}
	saved.AllowedDomains = domains
	if err := b.Svc.Store.PutSetting(settingKey, saved); err != nil {
		return Status{}, err
	}
	b.mu.Lock()
	b.settings.AllowedDomains = domains
	b.mu.Unlock()
	b.ids.reset()
	b.log().Info("slack allowed domains changed", "domains", domains, "by", admin.Login)
	return b.Status(), nil
}

// Disconnect revokes the bot token in Slack, forgets the tokens and stops.
func (b *Bot) Disconnect(ctx context.Context, admin jit.Identity) error {
	st := b.Status()
	if st.Source == "env" {
		return conflictf("Slack is set up in %s; remove %s and %s there, then restart jitd", b.EnvFile, EnvBotToken, EnvAppToken)
	}
	if api := b.client(); api != nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := api.AuthRevoke(cctx); err != nil {
			b.log().Warn("slack: revoking the bot token failed; it is forgotten anyway", "err", err)
		}
		cancel()
	}
	if err := b.Svc.Store.DeleteSetting(settingKey); err != nil {
		return err
	}
	b.apply(Settings{}, "")
	b.log().Info("slack disconnected", "by", admin.Login)
	return nil
}

// Channels lists the channels the bot can post to, cached for a few
// minutes.
func (b *Bot) Channels(ctx context.Context) ([]slack.Channel, error) {
	api := b.client()
	if api == nil {
		return nil, nil
	}
	b.cmu.Lock()
	defer b.cmu.Unlock()
	if b.channels != nil && b.now().Sub(b.channelAt) < 5*time.Minute {
		return b.channels, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cs, err := api.ListChannels(cctx)
	if err != nil {
		return nil, err
	}
	// Public channels take posts without an invite (chat:write.public);
	// private ones only list where the bot was invited.
	slices.SortFunc(cs, func(a, b slack.Channel) int { return strings.Compare(a.Name, b.Name) })
	b.channels, b.channelAt = cs, b.now()
	return cs, nil
}

// TestMessage posts a hello to a channel.
func (b *Bot) TestMessage(ctx context.Context, admin jit.Identity, channel string) error {
	api := b.client()
	if api == nil {
		return conflictf("Slack is not connected")
	}
	_, err := api.PostMessage(ctx, channel, slack.Message{
		Text: "Test message from JIT access",
		Blocks: []slack.Block{slack.Section(slack.Mrkdwn(fmt.Sprintf(":wave: Test message from <%s|JIT access>, sent by %s. Access requests for flows that use this channel show up here.",
			b.BaseURL, esc(admin.Login))))},
	})
	if err != nil {
		return badf("%s", explainPostError(err))
	}
	return nil
}

func explainPostError(err error) string {
	switch slack.ErrorCode(err) {
	case "not_in_channel":
		return "the bot is not in that channel: in Slack, type /invite @" + AppName + " in it"
	case "channel_not_found":
		return "Slack can't find that channel; for a private channel, invite the bot first (/invite @" + AppName + ")"
	case "is_archived":
		return "that channel is archived"
	}
	return err.Error()
}

// ---- notifications ----

// RequestChanged queues a look at the request's Slack messages. It never
// blocks (see jit.Notifier): if the queue is full the change is dropped,
// and the next reconcile catches up.
//
// The event itself is not used: the worker re-reads the request and redraws
// every message from its current state, which is what lets reconcile catch
// up after downtime. Anything that must happen once per transition needs
// its own record on the request.
func (b *Bot) RequestChanged(r *jit.AccessRequest, ev jit.Event) {
	b.init()
	select {
	case b.queue <- r.ID:
	default:
		b.log().Warn("slack: event queue full; the next reconcile will catch up", "id", r.ID)
	}
}

// worker handles changes one at a time, in order, so a message is posted
// before it is updated.
func (b *Bot) worker(ctx context.Context) {
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-b.queue:
			if api := b.client(); api != nil {
				b.sync(ctx, api, id)
			}
		case <-b.kick:
			b.reconcile(ctx)
		case <-t.C:
			b.reconcile(ctx)
		}
	}
}

// sync brings a request's Slack messages up to date: it posts them if the
// request is pending and was not announced yet, and updates the ones that
// were.
func (b *Bot) sync(ctx context.Context, api slack.API, id string) {
	r := b.Svc.Request(id)
	if r == nil {
		return
	}
	w, err := b.Svc.GetWorkflow(r.WorkflowID)
	if err != nil {
		w = nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if r.Status == jit.StatusPending && w != nil && w.Slack != nil {
		b.announce(cctx, api, r, w)
	}
	if len(r.Slack) > 0 {
		b.refresh(cctx, api, r, w)
	}
}

func (b *Bot) message(ctx context.Context, api slack.API, r *jit.AccessRequest, w *jit.Workflow) slack.Message {
	in := renderInput{R: r, W: w, URL: strings.TrimSuffix(b.BaseURL, "/") + "/requests/" + r.ID, Buttons: buttonsFor(w), Counted: len(r.Approvals)}
	if w != nil {
		cr := *r
		b.Svc.CountVotes(ctx, &cr)
		in.Counted = cr.ApprovalsCounted
	}
	if !r.Requester.Tagged() && r.Requester.Login != "" {
		if u, err := b.slackUser(ctx, api, r.Requester.Login); err == nil && b.userProblem(u) == "" {
			in.Mention = u.ID
		}
	}
	return render(in)
}

// announce posts a new request to the flow's channel and, if the flow says
// so, to each approver, unless that was done already. r.Slack is updated.
func (b *Bot) announce(ctx context.Context, api slack.API, r *jit.AccessRequest, w *jit.Workflow) {
	has := func(kind string) bool {
		return slices.ContainsFunc(r.Slack, func(m jit.SlackMessage) bool { return m.Kind == kind })
	}
	wantChannel := w.Slack.Channel != "" && !has("channel")
	wantDMs := w.Slack.DMApprovers && !has("dm")
	if !wantChannel && !wantDMs {
		return
	}
	msg := b.message(ctx, api, r, w)
	var posted []jit.SlackMessage
	if wantChannel {
		ts, err := api.PostMessage(ctx, w.Slack.Channel, msg)
		if err != nil {
			why := explainPostError(err)
			b.log().Warn("slack: posting a request to its channel", "id", r.ID, "channel", w.Slack.Channel, "err", why)
			b.setPostFailed(w.ID, why)
		} else {
			b.setPostFailed(w.ID, "")
			posted = append(posted, jit.SlackMessage{Channel: w.Slack.Channel, TS: ts, Kind: "channel"})
		}
	}
	if wantDMs {
		posted = append(posted, b.dmApprovers(ctx, api, r, w, msg)...)
	}
	if len(posted) == 0 {
		return
	}
	if err := b.Svc.RecordSlackMessages(r.ID, posted); err != nil {
		b.log().Error("slack: recording posted messages", "id", r.ID, "err", err)
	}
	r.Slack = append(r.Slack, posted...)
	b.setRendered(r.ID, digest(msg))
}

// dmApprovers sends the request to each approver who has a Slack account,
// except the requester.
func (b *Bot) dmApprovers(ctx context.Context, api slack.API, r *jit.AccessRequest, w *jit.Workflow, msg slack.Message) []jit.SlackMessage {
	var out []jit.SlackMessage
	logins, err := b.Svc.ApproverLogins(ctx, w)
	if err != nil {
		b.log().Warn("slack: direct messages to approvers", "id", r.ID, "err", err)
	}
	for _, login := range logins {
		if len(out) >= MaxDMs {
			b.log().Warn("slack: more approvers than direct messages allowed; the rest see the channel or the browser", "id", r.ID, "max", MaxDMs)
			break
		}
		if !r.Requester.Tagged() && strings.EqualFold(login, r.Requester.Login) {
			continue
		}
		u, err := b.slackUser(ctx, api, login)
		if err != nil || b.userProblem(u) != "" {
			continue
		}
		dm, err := api.OpenDM(ctx, u.ID)
		if err != nil {
			b.log().Warn("slack: opening a direct message", "id", r.ID, "approver", login, "err", err)
			continue
		}
		ts, err := api.PostMessage(ctx, dm, msg)
		if err != nil {
			b.log().Warn("slack: direct message to an approver", "id", r.ID, "approver", login, "err", err)
			continue
		}
		out = append(out, jit.SlackMessage{Channel: dm, TS: ts, Kind: "dm", User: u.ID})
	}
	return out
}

// refresh updates every message posted about r, unless it would not
// change.
func (b *Bot) refresh(ctx context.Context, api slack.API, r *jit.AccessRequest, w *jit.Workflow) {
	msg := b.message(ctx, api, r, w)
	d := digest(msg)
	if b.renderedDigest(r.ID) == d {
		return
	}
	failed := false
	for _, m := range r.Slack {
		if err := api.UpdateMessage(ctx, m.Channel, m.TS, msg); err != nil {
			if c := slack.ErrorCode(err); c == "message_not_found" || c == "channel_not_found" || c == "cant_update_message" {
				continue // deleted in Slack: nothing to update
			}
			failed = true
			b.log().Warn("slack: updating a request message", "id", r.ID, "channel", m.Channel, "err", err)
		}
	}
	if !failed {
		b.setRendered(r.ID, d)
	}
}

func (b *Bot) renderedDigest(id string) string {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	return b.rendered[id]
}

func (b *Bot) setRendered(id, d string) {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	if b.rendered == nil {
		b.rendered = map[string]string{}
	}
	b.rendered[id] = d
}

// reconcile catches up: pending requests not yet announced get posted, and
// recently changed requests get their messages updated if they are out of
// date (after a restart, every one of them is looked at once).
func (b *Bot) reconcile(ctx context.Context) {
	api := b.client()
	if api == nil {
		return
	}
	since := b.now().Add(-48 * time.Hour)
	rs := b.Svc.Requests(func(r *jit.AccessRequest) bool {
		return r.Status == jit.StatusPending || (len(r.Slack) > 0 && r.UpdatedAt.After(since))
	})
	slices.SortFunc(rs, func(a, b *jit.AccessRequest) int { return a.CreatedAt.Compare(b.CreatedAt) })
	for _, r := range rs {
		if ctx.Err() != nil {
			return
		}
		b.sync(ctx, api, r.ID)
	}
}

// ---- errors ----

func badf(format string, args ...any) error {
	return &jit.Error{Code: "bad_request", Status: 400, Message: fmt.Sprintf(format, args...)}
}

func conflictf(format string, args ...any) error {
	return &jit.Error{Code: "conflict", Status: 409, Message: fmt.Sprintf(format, args...)}
}

// errNotConnected is returned by checks that need Slack.
var errNotConnected = errors.New("Slack is not connected")
