// Package google is jitd's client for Google Groups. It adds and removes
// direct members of groups through the Cloud Identity Groups API, signed in
// as a service account that a super admin gave the Groups Admin role. It
// uses no domain-wide delegation and reads nothing about users: members are
// addressed by their email.
package google

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

// Where jitd talks to Google. These are fixed: nothing in a pasted key or a
// setting can point jitd, its signed assertion or its token anywhere else.
const (
	apiBase  = "https://cloudidentity.googleapis.com"
	tokenURL = "https://oauth2.googleapis.com/token"
	scope    = "https://www.googleapis.com/auth/cloud-identity.groups"
)

// Client is what jitd needs from Google Groups. Members are named by their
// email, lower-cased; groups by Group.ID.
type Client interface {
	// FindGroup looks a group up by its email, or by its ID. It returns
	// ErrNotFound for a group that does not exist and for one the service
	// account may not see: Google does not tell the two apart.
	FindGroup(ctx context.Context, ref string) (Group, error)
	// IsMember reports whether email is a direct member of the group.
	IsMember(ctx context.Context, groupID, email string) (bool, error)
	// AddMember makes email a member. It returns once Google has finished
	// the change. Adding someone who is a member already is not an error.
	AddMember(ctx context.Context, groupID, email string) error
	// RemoveMember takes email out of the group. Removing someone who is
	// not a member is not an error.
	RemoveMember(ctx context.Context, groupID, email string) error
	// Check tries the credential: that Google signs the service account in
	// and that the Cloud Identity API is on in its project. It cannot tell
	// whether the account holds the Groups Admin role; FindGroup on a real
	// group does.
	Check(ctx context.Context) error
}

// Group is a Google group.
type Group struct {
	ID    string // the part after "groups/" in Google's resource name
	Email string
	Name  string // the display name
	// Dynamic groups get their members from a query. Nobody can add to one.
	Dynamic bool
}

// Manageable reports whether members can be added to the group by hand.
func (g Group) Manageable() bool { return !g.Dynamic }

// APIError is the Cloud Identity API answering with an error.
type APIError struct {
	Method, Path string
	Status       int
	Code         string // Google's status, e.g. PERMISSION_DENIED
	Reason       string // from the error's details, e.g. SERVICE_DISABLED
	Message      string
	Body         string // the answer, cut short, when it was not Google's JSON
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("google API %s %s: %d %s (%s)", e.Method, e.Path, e.Status, e.Message, e.Code)
	}
	return fmt.Sprintf("google API %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

// Disabled reports whether the error says that the Cloud Identity API is
// not enabled in the service account's project.
func (e *APIError) Disabled() bool {
	return e.Reason == "SERVICE_DISABLED" || e.Reason == "accessNotConfigured" ||
		strings.Contains(e.Message, "has not been used in project") || strings.Contains(e.Message, "it is disabled")
}

func status(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// IsDisabled reports whether err says the Cloud Identity API is off.
func IsDisabled(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Disabled()
}

// IsRefusal reports whether err is Google answering that it did not do what
// was asked (a 4xx to the request that asks for the change). Any other
// failure (no answer, a timeout, a 5xx, a change Google had not finished,
// a 4xx to a question about a change Google had already taken) leaves open
// whether it was applied.
func IsRefusal(err error) bool {
	var u *unsettledError
	if errors.As(err, &u) {
		return false
	}
	s := status(err)
	return s >= 400 && s < 500
}

// unsettledError is a failure that leaves open whether a change was
// applied, whatever its cause looks like: a 4xx inside it is Google's
// answer to something else than the change itself.
type unsettledError struct{ err error }

func (e *unsettledError) Error() string { return e.err.Error() }
func (e *unsettledError) Unwrap() error { return e.err }

// hidden reports whether err is Google's answer for something that does
// not exist or that the service account may not see: a 404, or a 403 that
// is not about the API being off.
func hidden(err error) bool {
	s := status(err)
	return s == http.StatusNotFound || (s == http.StatusForbidden && !IsDisabled(err))
}

// ErrNotFound is returned by FindGroup when Google shows no such group.
var ErrNotFound = errors.New("not found in Google, or not visible to jitd's service account")

// NoGroupsError is a check that found the key working and none of the
// groups jitd uses visible. Google answers the same for a group that does
// not exist and for one the service account may not see, so this is the
// Groups Admin role missing (never assigned, or taken away) or the groups
// gone. Check alone cannot tell: its answer is the same with or without
// the role.
type NoGroupsError struct {
	Tried []string // the groups looked for, by address
}

func (e *NoGroupsError) Error() string {
	return "Google shows jitd's service account none of the groups jitd uses (looked for " + strings.Join(e.Tried, ", ") +
		"): the Groups Admin role is not assigned to it, or these groups no longer exist"
}

// errGroupGone is the group itself answering 404.
var errGroupGone = errors.New("Google no longer has this group")

// ErrUnconfigured is returned by every call of a Dynamic client while no
// service account key is set.
var ErrUnconfigured = errors.New("Google Groups is not configured: an admin can set it up on jitd's Google page (or set GOOGLE_SERVICE_ACCOUNT_JSON in jitd's env file)")

// The variables jitd's Google settings travel in.
const (
	// EnvKey holds the service account's JSON key, whole, on one line.
	EnvKey = "GOOGLE_SERVICE_ACCOUNT_JSON"
	// EnvDomains lists the email domains whose users jitd may add to
	// groups, separated by commas.
	EnvDomains = "GOOGLE_ALLOWED_DOMAINS"
	// EnvGrantAllowlist lists the groups (emails or IDs, * as a wildcard)
	// that approval flows may grant.
	EnvGrantAllowlist = "GOOGLE_GRANT_ALLOWLIST"
)

// Configured reports whether vars hold a service account key. It does not
// check that the key is well-formed: NewFromValues does.
func Configured(vars map[string]string) bool { return strings.TrimSpace(vars[EnvKey]) != "" }

// noRedirect is the HTTP client for Google. Its API does not redirect, and
// following one would send the signed assertion or the token to wherever
// the answer points.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// HTTP implements Client over net/http.
type HTTP struct {
	Key *Key
	// BaseURL and TokenURL are Google's. Only tests set them.
	BaseURL, TokenURL string
	HC                *http.Client
	Timeout           time.Duration // for one call, with its retries
	// Wait bounds how long AddMember and RemoveMember wait for Google to
	// finish a change it answered as still running.
	Wait time.Duration
	// Backoff is the pause before the first retry of a 429 or a 5xx, and
	// between looks at a change that is still running.
	Backoff time.Duration

	mu  sync.Mutex
	tok string
	exp time.Time
}

// NewFromValues builds a client from the service account key in
// vars[EnvKey].
func NewFromValues(vars map[string]string) (*HTTP, error) {
	if !Configured(vars) {
		return nil, ErrUnconfigured
	}
	k, err := ParseKey(vars[EnvKey])
	if err != nil {
		return nil, err
	}
	return &HTTP{Key: k, BaseURL: apiBase, TokenURL: tokenURL, HC: noRedirect, Timeout: 20 * time.Second, Wait: 15 * time.Second, Backoff: 300 * time.Millisecond}, nil
}

func (c *HTTP) hc() *http.Client {
	if c.HC != nil {
		return c.HC
	}
	return noRedirect
}

func (c *HTTP) backoff() time.Duration {
	if c.Backoff > 0 {
		return c.Backoff
	}
	return 300 * time.Millisecond
}

// The shapes of what Google names things. Names from its answers go into
// request paths, so they are checked first.
var (
	groupIDRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)
	membershipRE = regexp.MustCompile(`^groups/[A-Za-z0-9_-]{1,64}/memberships/[A-Za-z0-9_-]{1,64}$`)
	operationRE  = regexp.MustCompile(`^(?:[A-Za-z0-9_-]{1,100}/){0,6}operations/[A-Za-z0-9_-]{1,200}$`)
)

// IsGroupID reports whether ref has the shape of a group's ID (and so is
// not a group's email).
func IsGroupID(ref string) bool { return groupIDRE.MatchString(ref) }

// dynamicLabel marks a group whose members come from a query.
const dynamicLabel = "cloudidentity.googleapis.com/groups.dynamic"

// group reads one group by ID, passing Google's error on as it is.
func (c *HTTP) group(ctx context.Context, id string) (Group, error) {
	if !IsGroupID(id) {
		return Group{}, fmt.Errorf("%q is not a Google group ID", id)
	}
	var out struct {
		Name     string `json:"name"`
		GroupKey struct {
			ID string `json:"id"`
		} `json:"groupKey"`
		DisplayName string            `json:"displayName"`
		Labels      map[string]string `json:"labels"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/groups/"+id, nil, nil, &out); err != nil {
		return Group{}, err
	}
	if out.Name != "groups/"+id || out.GroupKey.ID == "" {
		return Group{}, fmt.Errorf("google API GET /v1/groups/%s: the answer is not that group", id)
	}
	g := Group{ID: id, Email: strings.ToLower(out.GroupKey.ID), Name: out.DisplayName}
	_, g.Dynamic = out.Labels[dynamicLabel]
	return g, nil
}

func (c *HTTP) FindGroup(ctx context.Context, ref string) (Group, error) {
	id := strings.TrimSpace(ref)
	if strings.Contains(id, "@") {
		var out struct {
			Name string `json:"name"`
		}
		err := c.do(ctx, http.MethodGet, "/v1/groups:lookup", url.Values{"groupKey.id": {strings.ToLower(id)}}, nil, &out)
		if hidden(err) {
			return Group{}, ErrNotFound
		}
		if err != nil {
			return Group{}, err
		}
		id = strings.TrimPrefix(out.Name, "groups/")
		if !IsGroupID(id) {
			return Group{}, errors.New("google API GET /v1/groups:lookup: the answer names no group")
		}
	} else if !IsGroupID(id) {
		return Group{}, ErrNotFound
	}
	g, err := c.group(ctx, id)
	if hidden(err) {
		return Group{}, ErrNotFound
	}
	return g, err
}

// membership returns the resource name of email's direct membership of the
// group, or "" when there is none.
//
// Google answers a lookup for someone who is not a member with a 404 or
// with a 403 ("permission denied ... or it may not exist"), the same as for
// a group the service account cannot see. So neither is taken as "not a
// member" until the group itself can be read. A group that answers 404 is
// errGroupGone; anything else is passed on.
func (c *HTTP) membership(ctx context.Context, groupID, email string) (string, error) {
	if !IsGroupID(groupID) {
		return "", fmt.Errorf("%q is not a Google group ID", groupID)
	}
	var out struct {
		Name string `json:"name"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/groups/"+groupID+"/memberships:lookup", url.Values{"memberKey.id": {strings.ToLower(email)}}, nil, &out)
	if err == nil {
		if !membershipRE.MatchString(out.Name) || !strings.HasPrefix(out.Name, "groups/"+groupID+"/") {
			return "", errors.New("google API GET memberships:lookup: the answer names no membership of this group")
		}
		return out.Name, nil
	}
	if !hidden(err) {
		return "", err
	}
	_, gerr := c.group(ctx, groupID)
	switch {
	case gerr == nil:
		return "", nil // the group is there and this address is not in it
	case status(gerr) == http.StatusNotFound:
		return "", fmt.Errorf("%w (%v)", errGroupGone, gerr)
	}
	return "", fmt.Errorf("%w; reading the group fails too, so jitd cannot tell whether the membership exists: %v", err, gerr)
}

func (c *HTTP) IsMember(ctx context.Context, groupID, email string) (bool, error) {
	name, err := c.membership(ctx, groupID, email)
	return name != "", err
}

// operation is Google's answer to a change: done, failed, or still running
// under a name to ask again with.
type operation struct {
	Name  string `json:"name"`
	Done  bool   `json:"done"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// finish waits until Google reports the change done. A change that failed,
// or that is still running when Wait is over, is an error that is not a
// refusal: the caller cannot assume it did not happen.
func (c *HTTP) finish(ctx context.Context, what string, op operation) error {
	wait := c.Wait
	if wait <= 0 {
		wait = 15 * time.Second
	}
	deadline := time.Now().Add(wait)
	for delay := c.backoff(); ; delay = min(delay*2, 2*time.Second) {
		switch {
		case op.Error != nil:
			return fmt.Errorf("google: %s failed: %s (code %d)", what, op.Error.Message, op.Error.Code)
		case op.Done:
			return nil
		case !operationRE.MatchString(op.Name):
			return fmt.Errorf("google: %s: Google did not say whether the change is done", what)
		case time.Now().After(deadline):
			return fmt.Errorf("google: %s: Google had not finished the change after %s", what, wait)
		}
		if err := sleep(ctx, delay); err != nil {
			return fmt.Errorf("google: %s: waiting for Google to finish the change: %w", what, err)
		}
		name := op.Name
		op = operation{}
		if err := c.do(ctx, http.MethodGet, "/v1/"+name, nil, nil, &op); err != nil {
			// Google took the change and now will not say how it went.
			return &unsettledError{fmt.Errorf("google: %s: asking Google whether the change is done: %w", what, err)}
		}
	}
}

func (c *HTTP) AddMember(ctx context.Context, groupID, email string) error {
	if !IsGroupID(groupID) {
		return fmt.Errorf("%q is not a Google group ID", groupID)
	}
	email = strings.ToLower(email)
	in := map[string]any{
		"preferredMemberKey": map[string]string{"id": email},
		"roles":              []map[string]string{{"name": "MEMBER"}},
	}
	var op operation
	err := c.do(ctx, http.MethodPost, "/v1/groups/"+groupID+"/memberships", nil, in, &op)
	if status(err) == http.StatusConflict {
		// Already a member, Google says. Believe it once the membership
		// shows. Until it does this is not a refusal: the 409 may be the
		// answer to a repeat of a request that Google applied the first
		// time (do repeats a POST after a 5xx), so the caller must treat
		// the member as possibly added.
		name, merr := c.membership(ctx, groupID, email)
		switch {
		case merr == nil && name != "":
			return nil
		case merr != nil:
			return &unsettledError{fmt.Errorf("%w; checking whether the address is a member failed too: %v", err, merr)}
		}
		return &unsettledError{fmt.Errorf("%w; yet the address does not show as a member of the group", err)}
	}
	if err != nil {
		return err
	}
	return c.finish(ctx, "adding the member", op)
}

// RemoveMember removes email from the group. Someone who is not a member
// counts as removed only when the group can be read (see membership). A
// group that is gone took its memberships with it, and that is believed
// only while the credential still works: a key for another project or a
// revoked role must not make jitd write a membership off.
func (c *HTTP) RemoveMember(ctx context.Context, groupID, email string) error {
	name, err := c.membership(ctx, groupID, email)
	if errors.Is(err, errGroupGone) {
		if cerr := c.Check(ctx); cerr != nil {
			return fmt.Errorf("%w; a test call fails as well, so the credential is probably wrong: %v", err, cerr)
		}
		return nil
	}
	if err != nil || name == "" {
		return err
	}
	var op operation
	err = c.do(ctx, http.MethodDelete, "/v1/"+name, nil, nil, &op)
	if status(err) == http.StatusNotFound {
		// Gone between the lookup and the delete? Only if a second lookup
		// says so.
		again, merr := c.membership(ctx, groupID, email)
		switch {
		case merr == nil && again == "", errors.Is(merr, errGroupGone):
			return nil
		case merr == nil:
			return fmt.Errorf("%w; the address is still listed as a member of the group", err)
		}
		return fmt.Errorf("%w; checking whether the membership is gone failed too: %v", err, merr)
	}
	if err != nil {
		return err
	}
	return c.finish(ctx, "removing the member", op)
}

// Check signs in and makes one harmless call: a lookup of a group by the
// service account's own address, which is never a group. Any answer but
// "sign in again" and "the API is off" shows that Google takes the key and
// that the Cloud Identity API is enabled.
//
// It does not show the Groups Admin role: without it Google answers this
// lookup just as it does with it. Only a group that is found shows the
// role (see NoGroupsError).
func (c *HTTP) Check(ctx context.Context) error {
	var out struct {
		Name string `json:"name"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/groups:lookup", url.Values{"groupKey.id": {strings.ToLower(c.Key.Email)}}, nil, &out)
	if hidden(err) || status(err) == http.StatusBadRequest {
		return nil
	}
	return err
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do makes one API call. The path never carries a query string (q does), so
// it is safe to log: a member's email is only ever in q.
func (c *HTTP) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
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
	target := c.BaseURL + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	var resp *http.Response
	var b []byte
	var rerr error
	// Two reasons to ask again, and every call jitd makes is safe to
	// repeat: a token Google rejects before it expires (once, with a fresh
	// one), and a 429 or a 5xx (twice, after a pause).
	renewed, retries := false, 0
	for {
		tok, err := c.token(ctx)
		if err != nil {
			return err
		}
		var body io.Reader
		if payload != nil {
			body = strings.NewReader(string(payload))
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("User-Agent", "jitd")
		resp, err = c.hc().Do(req)
		if err != nil {
			return fmt.Errorf("google API %s %s: %w", method, path, bare(err))
		}
		b, rerr = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && !renewed {
			c.forget(tok)
			renewed = true
			continue
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && retries < 2 {
			pause := c.backoff()
			if retries == 1 {
				pause *= 3
			}
			if sleep(ctx, pause) == nil {
				retries++
				continue
			}
		}
		break
	}
	if resp.StatusCode/100 != 2 {
		ae := &APIError{Method: method, Path: path, Status: resp.StatusCode}
		var ge struct {
			Error struct {
				Message string `json:"message"`
				Status  string `json:"status"`
				Details []struct {
					Reason string `json:"reason"`
				} `json:"details"`
			} `json:"error"`
		}
		if json.Unmarshal(b, &ge) == nil && ge.Error.Message != "" {
			ae.Code, ae.Message = ge.Error.Status, short(ge.Error.Message)
			for _, d := range ge.Error.Details {
				if d.Reason != "" {
					ae.Reason = d.Reason
					break
				}
			}
		} else {
			ae.Body = short(string(b))
		}
		return ae
	}
	if out != nil {
		// A body that was cut off, or is missing, must not read as an
		// answer.
		if rerr != nil {
			return fmt.Errorf("google API %s %s: reading response: %w", method, path, rerr)
		}
		if len(b) == 0 {
			return fmt.Errorf("google API %s %s: %d with an empty body", method, path, resp.StatusCode)
		}
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("google API %s %s: decoding response: %w", method, path, err)
		}
	}
	return nil
}
