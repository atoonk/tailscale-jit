package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Fake is an in-memory Slack for tests and the preview: canned users and
// channels, recorded posts, and a Socket Mode connection the test drives by
// pushing envelopes in and reading acks out.
type Fake struct {
	mu       sync.Mutex
	Bot      Auth
	Users    map[string]User    // by ID
	Channels map[string]Channel // by ID
	Posts    []Post
	Updates  []Post
	Ephem    []Post
	// Replies are slash command answers sent through Respond, keyed by
	// response URL.
	Replies map[string][]Message
	Views   []View
	Revoked bool
	// Fail makes the named method return this error code.
	Fail map[string]string
	// Opened counts ConnectionsOpen calls.
	Opened int

	conn   *fakeConn
	connMu sync.Mutex
}

// Post is one recorded message.
type Post struct {
	Channel, TS, User string
	Message           Message
}

// NewFake returns a Fake with a workspace, a bot and no users or channels.
func NewFake() *Fake {
	return &Fake{
		Bot:      Auth{URL: "https://example.slack.com/", Team: "Example Corp", User: "jit-access", TeamID: "T0FAKE", UserID: "UBOT", BotID: "BBOT"},
		Users:    map[string]User{},
		Channels: map[string]Channel{},
		Fail:     map[string]string{},
		Replies:  map[string][]Message{},
	}
}

// AddUser adds a full member with a confirmed email.
func (f *Fake) AddUser(id, email, realName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := User{ID: id, TeamID: f.Bot.TeamID, Name: strings.Split(email, "@")[0], RealName: realName, IsEmailConfirmed: true}
	u.Profile.Email = email
	u.Profile.DisplayName = realName
	f.Users[id] = u
}

// AddChannel adds a channel the bot is a member of.
func (f *Fake) AddChannel(id, name string, private bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Channels[id] = Channel{ID: id, Name: name, IsPrivate: private, IsMember: true}
}

func (f *Fake) fail(method string) error {
	if code := f.Fail[method]; code != "" {
		return &APIError{Method: method, Code: code, Status: 200}
	}
	return nil
}

func (f *Fake) AuthTest(ctx context.Context) (Auth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("auth.test"); err != nil {
		return Auth{}, err
	}
	if f.Revoked {
		return Auth{}, &APIError{Method: "auth.test", Code: "invalid_auth"}
	}
	return f.Bot, nil
}

func (f *Fake) AuthRevoke(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("auth.revoke"); err != nil {
		return err
	}
	f.Revoked = true
	return nil
}

func (f *Fake) ConnectionsOpen(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("apps.connections.open"); err != nil {
		return "", err
	}
	f.Opened++
	return "wss://fake.slack/" + fmt.Sprint(f.Opened), nil
}

func (f *Fake) PostMessage(ctx context.Context, channel string, m Message) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("chat.postMessage"); err != nil {
		return "", err
	}
	if c, ok := f.Channels[channel]; ok && !c.IsMember {
		return "", &APIError{Method: "chat.postMessage", Code: "not_in_channel"}
	}
	if _, ok := f.Channels[channel]; !ok && !strings.HasPrefix(channel, "D") {
		return "", &APIError{Method: "chat.postMessage", Code: "channel_not_found"}
	}
	ts := fmt.Sprintf("%d.%06d", 1700000000+len(f.Posts), len(f.Posts))
	f.Posts = append(f.Posts, Post{Channel: channel, TS: ts, Message: m})
	return ts, nil
}

func (f *Fake) UpdateMessage(ctx context.Context, channel, ts string, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("chat.update"); err != nil {
		return err
	}
	for i := range f.Posts {
		if f.Posts[i].Channel == channel && f.Posts[i].TS == ts {
			f.Posts[i].Message = m
			f.Updates = append(f.Updates, Post{Channel: channel, TS: ts, Message: m})
			return nil
		}
	}
	return &APIError{Method: "chat.update", Code: "message_not_found"}
}

func (f *Fake) PostEphemeral(ctx context.Context, channel, user string, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("chat.postEphemeral"); err != nil {
		return err
	}
	f.Ephem = append(f.Ephem, Post{Channel: channel, User: user, Message: m})
	return nil
}

// Respond records a slash command's reply.
func (f *Fake) Respond(ctx context.Context, responseURL string, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("response_url"); err != nil {
		return err
	}
	f.Replies[responseURL] = append(f.Replies[responseURL], m)
	return nil
}

// RepliesTo returns the replies sent to a slash command's response URL.
func (f *Fake) RepliesTo(responseURL string) []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Message(nil), f.Replies[responseURL]...)
}

// OpenView records v; its ID is "V" + its position in Views, counting from 1.
func (f *Fake) OpenView(ctx context.Context, triggerID string, v View) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("views.open"); err != nil {
		return "", err
	}
	f.Views = append(f.Views, v)
	return fmt.Sprintf("V%d", len(f.Views)), nil
}

// UpdateView replaces the view in Views that OpenView returned viewID for.
func (f *Fake) UpdateView(ctx context.Context, viewID string, v View) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("views.update"); err != nil {
		return err
	}
	var i int
	if _, err := fmt.Sscanf(viewID, "V%d", &i); err != nil || i < 1 || i > len(f.Views) {
		return &APIError{Method: "views.update", Code: "not_found"}
	}
	f.Views[i-1] = v
	return nil
}

func (f *Fake) UserInfo(ctx context.Context, id string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("users.info"); err != nil {
		return User{}, err
	}
	u, ok := f.Users[id]
	if !ok {
		return User{}, &APIError{Method: "users.info", Code: "user_not_found"}
	}
	return u, nil
}

func (f *Fake) LookupUserByEmail(ctx context.Context, email string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("users.lookupByEmail"); err != nil {
		return User{}, err
	}
	for _, u := range f.Users {
		if strings.EqualFold(u.Profile.Email, email) {
			return u, nil
		}
	}
	return User{}, &APIError{Method: "users.lookupByEmail", Code: "users_not_found"}
}

func (f *Fake) ListChannels(ctx context.Context) ([]Channel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("conversations.list"); err != nil {
		return nil, err
	}
	var out []Channel
	for _, c := range f.Channels {
		if !c.IsArchived {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *Fake) ChannelInfo(ctx context.Context, id string) (Channel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("conversations.info"); err != nil {
		return Channel{}, err
	}
	c, ok := f.Channels[id]
	if !ok {
		return Channel{}, &APIError{Method: "conversations.info", Code: "channel_not_found"}
	}
	return c, nil
}

func (f *Fake) OpenDM(ctx context.Context, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("conversations.open"); err != nil {
		return "", err
	}
	if _, ok := f.Users[user]; !ok {
		return "", &APIError{Method: "conversations.open", Code: "user_not_found"}
	}
	return "D" + strings.TrimPrefix(user, "U"), nil
}

// PostsTo returns the recorded posts to a channel.
func (f *Fake) PostsTo(channel string) []Post {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Post
	for _, p := range f.Posts {
		if p.Channel == channel {
			out = append(out, p)
		}
	}
	return out
}

// ---- Socket Mode ----

// Dial is the Dialer for the fake: it returns the fake's connection, so a
// test can push envelopes with Send and read acks with Acks.
func (f *Fake) Dial(ctx context.Context, url string) (Conn, error) {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	if f.conn != nil {
		f.conn.Close()
	}
	f.conn = &fakeConn{in: make(chan []byte, 64), out: make(chan []byte, 64), done: make(chan struct{})}
	hello, _ := json.Marshal(map[string]any{"type": "hello"})
	f.conn.in <- hello
	return f.conn, nil
}

func (f *Fake) current() *fakeConn {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	return f.conn
}

// Connected reports whether a Socket has dialled the fake.
func (f *Fake) Connected() bool { return f.current() != nil }

// Send pushes an envelope to the connected Socket as Slack would.
func (f *Fake) Send(env Envelope) error {
	c := f.current()
	if c == nil {
		return ErrClosed
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	select {
	case c.in <- b:
		return nil
	case <-c.done:
		return ErrClosed
	}
}

// Acks returns the channel of frames the Socket wrote (acks).
func (f *Fake) Acks() <-chan []byte {
	c := f.current()
	if c == nil {
		return nil
	}
	return c.out
}

// Drop closes the connection from Slack's side, so the Socket reconnects.
func (f *Fake) Drop() {
	if c := f.current(); c != nil {
		c.Close()
	}
}

type fakeConn struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func (c *fakeConn) Read(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.in:
		return b, nil
	case <-c.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeConn) Write(ctx context.Context, b []byte) error {
	select {
	case c.out <- b:
		return nil
	case <-c.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

// Interactive builds an interactive envelope for a button click by user on
// the message in channel.
func Interactive(user, channel, ts, actionID, value string) Envelope {
	p, _ := json.Marshal(map[string]any{
		"type": "block_actions", "trigger_id": "trig." + ts, "user": map[string]string{"id": user},
		"channel": map[string]string{"id": channel}, "container": map[string]string{"channel_id": channel, "message_ts": ts},
		"actions": []map[string]string{{"action_id": actionID, "block_id": "jit_actions", "value": value}},
	})
	return Envelope{EnvelopeID: "env-" + actionID + "-" + ts, Type: "interactive", Payload: p}
}

// Submission builds a view_submission envelope for a modal.
func Submission(user, callbackID, private string, values map[string]map[string]string) Envelope {
	vals := map[string]map[string]map[string]string{}
	for block, acts := range values {
		vals[block] = map[string]map[string]string{}
		for act, v := range acts {
			vals[block][act] = map[string]string{"type": "plain_text_input", "value": v}
		}
	}
	p, _ := json.Marshal(map[string]any{
		"type": "view_submission", "user": map[string]string{"id": user},
		"view": map[string]any{"id": "V1", "callback_id": callbackID, "private_metadata": private, "state": map[string]any{"values": vals}},
	})
	return Envelope{EnvelopeID: "env-view-" + private, Type: "interactive", Payload: p, AcceptsResponsePayload: true}
}

// Command builds a slash_commands envelope.
func Command(user, channel, command, text string) Envelope {
	p, _ := json.Marshal(SlashCommand{Command: command, Text: text, UserID: user, ChannelID: channel, TriggerID: "trig.cmd",
		ResponseURL: CommandResponseURL(text)})
	return Envelope{EnvelopeID: "env-cmd-" + text, Type: "slash_commands", Payload: p, AcceptsResponsePayload: true}
}

// CommandResponseURL is the response URL the fake gives a /jit command
// with this text.
func CommandResponseURL(text string) string {
	return "https://hooks.slack.com/commands/fake/" + strings.ReplaceAll(strings.TrimSpace(text), " ", "_")
}

// EphemeralPosts returns the ephemeral replies so far.
func (f *Fake) EphemeralPosts() []Post {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Post(nil), f.Ephem...)
}

// OpenedViews returns the modals opened so far.
func (f *Fake) OpenedViews() []View {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]View(nil), f.Views...)
}

// SetFail makes method fail with code; an empty code clears it.
func (f *Fake) SetFail(method, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if code == "" {
		delete(f.Fail, method)
	} else {
		f.Fail[method] = code
	}
}

// MakeGuest turns a user into a guest account.
func (f *Fake) SetUser(id string, change func(*User)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.Users[id]
	change(&u)
	f.Users[id] = u
}

// MakeGuest turns a user into a guest.
func (f *Fake) MakeGuest(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.Users[id]
	u.IsRestricted = true
	f.Users[id] = u
}

// IsRevoked reports whether the bot token was revoked.
func (f *Fake) IsRevoked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Revoked
}
