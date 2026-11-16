// Package okta is a minimal client for the parts of the Okta management API
// that jitd needs to grant time-limited membership in Okta groups: finding a
// user and a group, and adding, checking and removing a group member.
package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Client is the subset of the Okta API used by jitd, so tests can fake it.
type Client interface {
	// FindUser returns the Okta user whose login (or, failing that, primary
	// email) is login.
	FindUser(ctx context.Context, login string) (User, error)
	// FindGroup returns a group by its ID (00g…) or its exact name.
	FindGroup(ctx context.Context, ref string) (Group, error)
	// IsMember reports whether user is a direct member of group.
	IsMember(ctx context.Context, groupID, userID string) (bool, error)
	// AddMember adds user to group. Adding an existing member is a no-op.
	AddMember(ctx context.Context, groupID, userID string) error
	// RemoveMember removes user from group. Removing a non-member is a no-op.
	RemoveMember(ctx context.Context, groupID, userID string) error
	// UserGroups lists every group user is a member of, of any type.
	UserGroups(ctx context.Context, userID string) ([]Group, error)
	// GroupMembers lists the members of group, up to MaxGroupMembers.
	GroupMembers(ctx context.Context, groupID string) ([]User, error)
	// Check makes one cheap call to see that the credentials work.
	Check(ctx context.Context) error
}

// MaxGroupMembers caps GroupMembers, so one huge group cannot stall jitd.
const MaxGroupMembers = 2000

// Key is how a user is matched against a Tailscale login: their primary
// email, or their login if they have none, lowercased.
func (u User) Key() string {
	if u.Profile.Email != "" {
		return strings.ToLower(u.Profile.Email)
	}
	return strings.ToLower(u.Profile.Login)
}

// Matches reports whether g is the group ref names, by ID or exact name.
func (g Group) Matches(ref string) bool { return g.ID == ref || g.Profile.Name == ref }

// User is the part of an Okta user jitd looks at.
type User struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login string `json:"login"`
		Email string `json:"email"`
	} `json:"profile"`
}

// Group is the part of an Okta group jitd looks at.
type Group struct {
	ID      string `json:"id"`
	Type    string `json:"type"` // OKTA_GROUP, APP_GROUP, BUILT_IN
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

// Name is the group's display name.
func (g Group) Name() string { return g.Profile.Name }

// Manageable reports whether Okta lets an API client change the group's
// members. Groups mastered by a directory or app (APP_GROUP) and built-in
// groups (Everyone) are not.
func (g Group) Manageable() bool { return g.Type == "" || g.Type == "OKTA_GROUP" }

// APIError is a non-2xx response from the Okta API.
type APIError struct {
	Method, Path string
	Status       int
	Code         string // Okta's errorCode, e.g. E0000007
	Summary      string // Okta's errorSummary
	Body         string
}

func (e *APIError) Error() string {
	if e.Summary != "" {
		return fmt.Sprintf("okta API %s %s: %d %s (%s)", e.Method, e.Path, e.Status, e.Summary, e.Code)
	}
	return fmt.Sprintf("okta API %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

// IsNotFound reports whether err is a 404 from the Okta API.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// ErrNotFound is returned by FindUser and FindGroup when nothing matches.
var ErrNotFound = errors.New("not found in Okta")

// ErrUnconfigured is returned by every call of a Dynamic client while no
// Okta credentials are set.
var ErrUnconfigured = errors.New("Okta is not configured: set OKTA_ORG_URL and either OKTA_API_TOKEN or OKTA_CLIENT_ID and OKTA_PRIVATE_KEY in jitd's env file")

// CredentialVars are the variables NewFromValues looks at.
var CredentialVars = []string{"OKTA_ORG_URL", "OKTA_API_TOKEN", "OKTA_CLIENT_ID", "OKTA_PRIVATE_KEY", "OKTA_PRIVATE_KEY_ID", "OKTA_SCOPES"}

// Configured reports whether vars set an Okta org and some credential for
// it (an API token, or a service app). It does not check that they are
// complete or valid: NewFromValues does.
func Configured(vars map[string]string) bool {
	return vars["OKTA_ORG_URL"] != "" && (vars["OKTA_API_TOKEN"] != "" || vars["OKTA_CLIENT_ID"] != "" || vars["OKTA_PRIVATE_KEY"] != "")
}

// HTTP implements Client over net/http, signed in with either an Okta API
// token (SSWS) or, when OAuth is set, as an OAuth service app.
type HTTP struct {
	BaseURL string // https://example.okta.com
	Token   string
	OAuth   *OAuth
	HC      *http.Client
	Timeout time.Duration
}

// NewFromValues builds a client from OKTA_ORG_URL and either OKTA_API_TOKEN
// or a service app (OKTA_CLIENT_ID, OKTA_PRIVATE_KEY and the optional
// OKTA_PRIVATE_KEY_ID and OKTA_SCOPES; see OAuth).
func NewFromValues(vars map[string]string) (*HTTP, error) {
	if !Configured(vars) {
		return nil, ErrUnconfigured
	}
	token := strings.TrimSpace(vars["OKTA_API_TOKEN"])
	app := vars["OKTA_CLIENT_ID"] != "" || vars["OKTA_PRIVATE_KEY"] != ""
	if token != "" && app {
		return nil, errors.New("set either OKTA_API_TOKEN or OKTA_CLIENT_ID and OKTA_PRIVATE_KEY, not both")
	}
	base := strings.TrimSuffix(strings.TrimSpace(vars["OKTA_ORG_URL"]), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("OKTA_ORG_URL %q is not a URL like https://example.okta.com", base)
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return nil, fmt.Errorf("OKTA_ORG_URL %q must use https", base)
	}
	c := &HTTP{BaseURL: base, Token: token, HC: http.DefaultClient, Timeout: 15 * time.Second}
	if app {
		o, err := newOAuth(base, vars)
		if err != nil {
			return nil, err
		}
		c.OAuth = o
	}
	return c, nil
}

// groupIDRE is the shape of an Okta group ID.
var groupIDRE = regexp.MustCompile(`^00g[A-Za-z0-9]{10,}$`)

// IsGroupID reports whether ref looks like an Okta group ID rather than a name.
func IsGroupID(ref string) bool { return groupIDRE.MatchString(ref) }

func (c *HTTP) FindUser(ctx context.Context, login string) (User, error) {
	var u User
	err := c.do(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(login), nil, &u, nil)
	if err == nil {
		return u, nil
	}
	if !IsNotFound(err) {
		return User{}, err
	}
	// Not a login: try the primary email, which is what Tailscale usually
	// knows a person by when the two differ.
	var us []User
	q := url.Values{"search": {fmt.Sprintf("profile.email eq %q", login)}, "limit": {"2"}}
	if err := c.do(ctx, http.MethodGet, "/api/v1/users?"+q.Encode(), nil, &us, nil); err != nil {
		return User{}, err
	}
	switch len(us) {
	case 0:
		return User{}, fmt.Errorf("user %s: %w", login, ErrNotFound)
	case 1:
		return us[0], nil
	}
	return User{}, fmt.Errorf("more than one Okta user has the email %s", login)
}

func (c *HTTP) FindGroup(ctx context.Context, ref string) (Group, error) {
	ref = strings.TrimSpace(ref)
	if IsGroupID(ref) {
		var g Group
		err := c.do(ctx, http.MethodGet, "/api/v1/groups/"+url.PathEscape(ref), nil, &g, nil)
		if IsNotFound(err) {
			return Group{}, fmt.Errorf("group %s: %w", ref, ErrNotFound)
		}
		return g, err
	}
	// q is a prefix match on the name: keep only exact matches.
	var gs []Group
	q := url.Values{"q": {ref}, "limit": {"200"}}
	if err := c.do(ctx, http.MethodGet, "/api/v1/groups?"+q.Encode(), nil, &gs, nil); err != nil {
		return Group{}, err
	}
	var hits []Group
	for _, g := range gs {
		if g.Profile.Name == ref {
			hits = append(hits, g)
		}
	}
	switch len(hits) {
	case 0:
		return Group{}, fmt.Errorf("group %q: %w", ref, ErrNotFound)
	case 1:
		return hits[0], nil
	}
	return Group{}, fmt.Errorf("more than one Okta group is named %q; use its ID (00g…)", ref)
}

func (c *HTTP) IsMember(ctx context.Context, groupID, userID string) (bool, error) {
	gs, err := c.UserGroups(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, g := range gs {
		if g.ID == groupID {
			return true, nil
		}
	}
	return false, nil
}

func (c *HTTP) UserGroups(ctx context.Context, userID string) ([]Group, error) {
	var out []Group
	next := "/api/v1/users/" + url.PathEscape(userID) + "/groups"
	for next != "" {
		var gs []Group
		var link string
		if err := c.do(ctx, http.MethodGet, next, nil, &gs, &link); err != nil {
			return nil, err
		}
		out = append(out, gs...)
		next = c.nextPath(link)
	}
	return out, nil
}

func (c *HTTP) GroupMembers(ctx context.Context, groupID string) ([]User, error) {
	var out []User
	next := "/api/v1/groups/" + url.PathEscape(groupID) + "/users?limit=200"
	for next != "" && len(out) < MaxGroupMembers {
		var us []User
		var link string
		if err := c.do(ctx, http.MethodGet, next, nil, &us, &link); err != nil {
			return nil, err
		}
		out = append(out, us...)
		next = c.nextPath(link)
	}
	if len(out) > MaxGroupMembers {
		out = out[:MaxGroupMembers]
	}
	return out, nil
}

func memberPath(groupID, userID string) string {
	return "/api/v1/groups/" + url.PathEscape(groupID) + "/users/" + url.PathEscape(userID)
}

// Check lists one group: it needs the same rights as the rest of jitd's
// calls, and it counts as use of the token.
func (c *HTTP) Check(ctx context.Context) error {
	var gs []Group
	return c.do(ctx, http.MethodGet, "/api/v1/groups?limit=1", nil, &gs, nil)
}

func (c *HTTP) AddMember(ctx context.Context, groupID, userID string) error {
	return c.do(ctx, http.MethodPut, memberPath(groupID, userID), nil, nil, nil)
}

func (c *HTTP) RemoveMember(ctx context.Context, groupID, userID string) error {
	err := c.do(ctx, http.MethodDelete, memberPath(groupID, userID), nil, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// nextPath extracts the rel="next" URL from a Link header, as a path on
// BaseURL; links pointing anywhere else are ignored.
func (c *HTTP) nextPath(link string) string {
	for _, part := range strings.Split(link, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		target = strings.Trim(strings.TrimSpace(target), "<>")
		if p, ok := strings.CutPrefix(target, c.BaseURL); ok && strings.HasPrefix(p, "/") {
			return p
		}
	}
	return ""
}

func (c *HTTP) do(ctx context.Context, method, path string, in, out any, link *string) error {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	var payload []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		payload = b
	}
	hc := c.HC
	if hc == nil {
		hc = http.DefaultClient
	}
	var resp *http.Response
	var b []byte
	// A service app's token can be rejected before it expires (its key or
	// grants changed): fetch a fresh one and try once more. Every call jitd
	// makes is safe to repeat.
	for attempt := 0; ; attempt++ {
		auth := "SSWS " + c.Token
		var tok string
		if c.OAuth != nil {
			var err error
			if tok, err = c.OAuth.token(ctx, hc); err != nil {
				return err
			}
			auth = "Bearer " + tok
		}
		var body io.Reader
		if payload != nil {
			body = strings.NewReader(string(payload))
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		req.Header.Set("User-Agent", "jitd")
		resp, err = hc.Do(req)
		if err != nil {
			return fmt.Errorf("okta API %s %s: %w", method, logPath(path), err)
		}
		b, _ = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && c.OAuth != nil && attempt == 0 {
			c.OAuth.forget(tok)
			continue
		}
		break
	}
	if resp.StatusCode/100 != 2 {
		ae := &APIError{Method: method, Path: logPath(path), Status: resp.StatusCode}
		var oe struct {
			ErrorCode    string `json:"errorCode"`
			ErrorSummary string `json:"errorSummary"`
		}
		if json.Unmarshal(b, &oe) == nil && oe.ErrorSummary != "" {
			ae.Code, ae.Summary = oe.ErrorCode, oe.ErrorSummary
		} else {
			ae.Body = strings.TrimSpace(string(b))
			if len(ae.Body) > 512 {
				ae.Body = ae.Body[:512]
			}
		}
		return ae
	}
	if link != nil {
		*link = strings.Join(resp.Header.Values("Link"), ",")
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("okta API %s %s: decoding response: %w", method, logPath(path), err)
		}
	}
	return nil
}

// logPath drops the query string, which can carry a person's email.
func logPath(p string) string {
	p, _, _ = strings.Cut(p, "?")
	return p
}

// Dynamic is a Client that (re)builds its backing HTTP client from Load on
// each call, so editing the env file takes effect without a restart. Until
// Load returns a complete credential, every call fails with ErrUnconfigured.
type Dynamic struct {
	Load func() map[string]string

	mu   sync.Mutex
	key  string
	c    Client
	berr error
}

// Enabled reports whether Okta credentials are present (not whether they work).
func (d *Dynamic) Enabled() bool {
	_, err := d.get()
	return err == nil
}

func (d *Dynamic) get() (Client, error) {
	vars := map[string]string{}
	if d.Load != nil {
		vars = d.Load()
	}
	var parts []string
	for _, k := range CredentialVars {
		parts = append(parts, vars[k])
	}
	key := strings.Join(parts, "\x00")
	d.mu.Lock()
	defer d.mu.Unlock()
	if key != d.key || (d.c == nil && d.berr == nil) {
		d.key = key
		c, err := NewFromValues(vars)
		d.c, d.berr = nil, err
		if err == nil {
			d.c = c
		}
	}
	if d.berr != nil {
		return nil, d.berr
	}
	return d.c, nil
}

func (d *Dynamic) FindUser(ctx context.Context, login string) (User, error) {
	c, err := d.get()
	if err != nil {
		return User{}, err
	}
	return c.FindUser(ctx, login)
}

func (d *Dynamic) FindGroup(ctx context.Context, ref string) (Group, error) {
	c, err := d.get()
	if err != nil {
		return Group{}, err
	}
	return c.FindGroup(ctx, ref)
}

func (d *Dynamic) IsMember(ctx context.Context, groupID, userID string) (bool, error) {
	c, err := d.get()
	if err != nil {
		return false, err
	}
	return c.IsMember(ctx, groupID, userID)
}

func (d *Dynamic) AddMember(ctx context.Context, groupID, userID string) error {
	c, err := d.get()
	if err != nil {
		return err
	}
	return c.AddMember(ctx, groupID, userID)
}

func (d *Dynamic) UserGroups(ctx context.Context, userID string) ([]Group, error) {
	c, err := d.get()
	if err != nil {
		return nil, err
	}
	return c.UserGroups(ctx, userID)
}

func (d *Dynamic) GroupMembers(ctx context.Context, groupID string) ([]User, error) {
	c, err := d.get()
	if err != nil {
		return nil, err
	}
	return c.GroupMembers(ctx, groupID)
}

func (d *Dynamic) Check(ctx context.Context) error {
	c, err := d.get()
	if err != nil {
		return err
	}
	return c.Check(ctx)
}

func (d *Dynamic) RemoveMember(ctx context.Context, groupID, userID string) error {
	c, err := d.get()
	if err != nil {
		return err
	}
	return c.RemoveMember(ctx, groupID, userID)
}
