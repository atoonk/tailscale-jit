// Package slack is the little of Slack that jitd needs: a few Web API
// methods, Socket Mode (jitd dials out; Slack never connects in) and the
// Block Kit pieces of an approval message. It is written against the wire
// format on purpose: the protocol is small, and it keeps jitd's dependencies
// as they are.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is Slack's Web API.
const DefaultBaseURL = "https://slack.com/api"

// API is what jitd calls on Slack. The real implementation is Client; the
// Fake stands in for tests and the preview.
type API interface {
	// AuthTest says who the bot token is (auth.test).
	AuthTest(ctx context.Context) (Auth, error)
	// AuthRevoke invalidates the bot token (auth.revoke).
	AuthRevoke(ctx context.Context) error
	// ConnectionsOpen returns a Socket Mode WebSocket URL, good for one
	// connection (apps.connections.open, with the app-level token).
	ConnectionsOpen(ctx context.Context) (string, error)
	PostMessage(ctx context.Context, channel string, m Message) (ts string, err error)
	UpdateMessage(ctx context.Context, channel, ts string, m Message) error
	PostEphemeral(ctx context.Context, channel, user string, m Message) error
	// Respond answers a slash command through its response_url, after the
	// ack: the reply is seen by the caller only.
	Respond(ctx context.Context, responseURL string, m Message) error
	OpenView(ctx context.Context, triggerID string, v View) (viewID string, err error)
	UpdateView(ctx context.Context, viewID string, v View) error
	UserInfo(ctx context.Context, id string) (User, error)
	LookupUserByEmail(ctx context.Context, email string) (User, error)
	// ListChannels lists the public and private channels the bot can see,
	// across pages. Archived channels are left out.
	ListChannels(ctx context.Context) ([]Channel, error)
	ChannelInfo(ctx context.Context, id string) (Channel, error)
	// OpenDM returns the direct-message conversation with a user.
	OpenDM(ctx context.Context, user string) (channel string, err error)
}

// Auth is the answer to auth.test.
type Auth struct {
	URL    string `json:"url"`
	Team   string `json:"team"`
	User   string `json:"user"`
	TeamID string `json:"team_id"`
	UserID string `json:"user_id"`
	BotID  string `json:"bot_id"`
}

// User is a Slack user, the parts that matter for identity.
type User struct {
	ID                string `json:"id"`
	TeamID            string `json:"team_id"` // the user's home workspace
	Name              string `json:"name"`
	RealName          string `json:"real_name"`
	Deleted           bool   `json:"deleted"`
	IsBot             bool   `json:"is_bot"`
	IsRestricted      bool   `json:"is_restricted"`       // guest
	IsUltraRestricted bool   `json:"is_ultra_restricted"` // single-channel guest
	IsEmailConfirmed  bool   `json:"is_email_confirmed"`
	Profile           struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	} `json:"profile"`
}

// Channel is a conversation the bot can post to.
type Channel struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsPrivate  bool   `json:"is_private"`
	IsMember   bool   `json:"is_member"`
	IsArchived bool   `json:"is_archived"`
}

// APIError is a Slack error reply, {"ok": false, "error": "..."}.
type APIError struct {
	Method string
	Code   string // Slack's error name, e.g. not_in_channel, invalid_auth
	Status int
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("slack %s: HTTP %d", e.Method, e.Status)
	}
	return fmt.Sprintf("slack %s: %s", e.Method, e.Code)
}

// ErrorCode returns Slack's error name from err, or "".
func ErrorCode(err error) string {
	var e *APIError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Client calls the Slack Web API.
type Client struct {
	HTTP     *http.Client
	BaseURL  string // DefaultBaseURL if empty
	BotToken string // xoxb-…, for everything but Socket Mode
	AppToken string // xapp-…, for apps.connections.open
}

// New returns a client with a 20 s timeout.
func New(botToken, appToken string) *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, BotToken: botToken, AppToken: appToken}
}

func (c *Client) base() string {
	if c.BaseURL == "" {
		return DefaultBaseURL
	}
	return strings.TrimSuffix(c.BaseURL, "/")
}

// call posts a method. Read methods take form fields; write methods with
// nested blocks take JSON (Slack only parses JSON for those). The reply's
// envelope is checked and the whole body decoded into out, if given.
func (c *Client) call(ctx context.Context, method, token string, form url.Values, body any, out any) error {
	var rd io.Reader
	ctype := "application/x-www-form-urlencoded"
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd, ctype = bytes.NewReader(b), "application/json; charset=utf-8"
	} else if form != nil {
		rd = strings.NewReader(form.Encode())
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/"+method, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", ctype)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("slack %s: %w", method, err)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("slack %s: %w", method, err)
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			// Slack says how long to wait; once is enough for a service
			// this quiet.
			wait := 2 * time.Second
			if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 && n <= 30 {
				wait = time.Duration(n) * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			// The body readers were consumed; rebuild them.
			if body != nil {
				bb, _ := json.Marshal(body)
				rd = bytes.NewReader(bb)
			} else if form != nil {
				rd = strings.NewReader(form.Encode())
			}
			continue
		}
		var env struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if resp.StatusCode/100 != 2 || json.Unmarshal(b, &env) != nil {
			return &APIError{Method: method, Status: resp.StatusCode}
		}
		if !env.OK {
			return &APIError{Method: method, Code: env.Error, Status: resp.StatusCode}
		}
		if out != nil {
			if err := json.Unmarshal(b, out); err != nil {
				return fmt.Errorf("slack %s: decoding reply: %w", method, err)
			}
		}
		return nil
	}
}

func (c *Client) AuthTest(ctx context.Context) (Auth, error) {
	var a Auth
	err := c.call(ctx, "auth.test", c.BotToken, url.Values{}, nil, &a)
	return a, err
}

func (c *Client) AuthRevoke(ctx context.Context) error {
	return c.call(ctx, "auth.revoke", c.BotToken, url.Values{}, nil, nil)
}

func (c *Client) ConnectionsOpen(ctx context.Context) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	err := c.call(ctx, "apps.connections.open", c.AppToken, url.Values{}, nil, &out)
	return out.URL, err
}

func (c *Client) PostMessage(ctx context.Context, channel string, m Message) (string, error) {
	var out struct {
		TS string `json:"ts"`
	}
	err := c.call(ctx, "chat.postMessage", c.BotToken, nil, m.body(channel), &out)
	return out.TS, err
}

func (c *Client) UpdateMessage(ctx context.Context, channel, ts string, m Message) error {
	body := m.body(channel)
	body["ts"] = ts
	return c.call(ctx, "chat.update", c.BotToken, nil, body, nil)
}

func (c *Client) PostEphemeral(ctx context.Context, channel, user string, m Message) error {
	body := m.body(channel)
	body["user"] = user
	return c.call(ctx, "chat.postEphemeral", c.BotToken, nil, body, nil)
}

// Respond posts an ephemeral reply to a slash command's response_url. The
// URL comes from Slack over the Socket Mode connection; only Slack's own
// hooks host is accepted, so a bad payload can't make jitd post elsewhere.
func (c *Client) Respond(ctx context.Context, responseURL string, m Message) error {
	u, err := url.Parse(responseURL)
	if err != nil || u.Scheme != "https" || u.Host != "hooks.slack.com" {
		return fmt.Errorf("slack: not a Slack response URL: %q", responseURL)
	}
	body := Ephemeral(m)
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("slack response_url: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return &APIError{Method: "response_url", Status: resp.StatusCode}
	}
	return nil
}

func (c *Client) OpenView(ctx context.Context, triggerID string, v View) (string, error) {
	var out struct {
		View struct {
			ID string `json:"id"`
		} `json:"view"`
	}
	err := c.call(ctx, "views.open", c.BotToken, nil, map[string]any{"trigger_id": triggerID, "view": v}, &out)
	return out.View.ID, err
}

// UpdateView replaces an open modal. Unlike views.open it has no 3-second
// deadline, so a modal can open with a placeholder and fill in later.
func (c *Client) UpdateView(ctx context.Context, viewID string, v View) error {
	return c.call(ctx, "views.update", c.BotToken, nil, map[string]any{"view_id": viewID, "view": v}, nil)
}

func (c *Client) UserInfo(ctx context.Context, id string) (User, error) {
	var out struct {
		User User `json:"user"`
	}
	err := c.call(ctx, "users.info", c.BotToken, url.Values{"user": {id}}, nil, &out)
	return out.User, err
}

func (c *Client) LookupUserByEmail(ctx context.Context, email string) (User, error) {
	var out struct {
		User User `json:"user"`
	}
	err := c.call(ctx, "users.lookupByEmail", c.BotToken, url.Values{"email": {email}}, nil, &out)
	return out.User, err
}

func (c *Client) ListChannels(ctx context.Context) ([]Channel, error) {
	var all []Channel
	cursor := ""
	for page := 0; page < 20; page++ {
		form := url.Values{"types": {"public_channel,private_channel"}, "exclude_archived": {"true"}, "limit": {"200"}}
		if cursor != "" {
			form.Set("cursor", cursor)
		}
		var out struct {
			Channels []Channel `json:"channels"`
			Meta     struct {
				Next string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := c.call(ctx, "conversations.list", c.BotToken, form, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Channels...)
		cursor = out.Meta.Next
		if cursor == "" {
			break
		}
	}
	return all, nil
}

func (c *Client) ChannelInfo(ctx context.Context, id string) (Channel, error) {
	var out struct {
		Channel Channel `json:"channel"`
	}
	err := c.call(ctx, "conversations.info", c.BotToken, url.Values{"channel": {id}}, nil, &out)
	return out.Channel, err
}

func (c *Client) OpenDM(ctx context.Context, user string) (string, error) {
	var out struct {
		Channel struct {
			ID string `json:"id"`
		} `json:"channel"`
	}
	err := c.call(ctx, "conversations.open", c.BotToken, nil, map[string]any{"users": user}, &out)
	return out.Channel.ID, err
}
