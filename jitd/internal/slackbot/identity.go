package slackbot

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
)

// How long a Slack user's identity is remembered. Short, so a deactivated
// account or a changed email stops working soon; long enough that a click
// costs no Slack call most of the time.
const (
	identityTTL = 10 * time.Minute
	failureTTL  = time.Minute
)

// identities maps Slack users to Tailscale logins and back, with a cache.
type identities struct {
	mu      sync.Mutex
	byUser  map[string]cachedIdentity // Slack user ID -> identity
	byLogin map[string]cachedUser     // lowercased login -> Slack user
}

type cachedIdentity struct {
	id  jit.Identity
	err error
	at  time.Time
}

type cachedUser struct {
	user slack.User
	err  error
	at   time.Time
}

func (c *identities) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byUser, c.byLogin = nil, nil
}

// IdentityError says why a Slack user cannot act in jitd.
type IdentityError struct{ Msg string }

func (e *IdentityError) Error() string { return e.Msg }

// resolve matches the Slack user to a Tailscale login by their Slack email.
// Only full members of the connected workspace (no guests, bots,
// deactivated accounts or people from other workspaces) with a confirmed
// email in an allowed domain are matched, and only if that login is on the
// tailnet: it owns at least one device there. Without that, Slack would let
// people act who could never use jitd in the browser (someone offboarded
// from Tailscale but still in Slack would count as autogroup:member).
func (b *Bot) resolve(ctx context.Context, api slack.API, userID string) (jit.Identity, error) {
	now := b.now()
	c := &b.ids
	c.mu.Lock()
	if e, ok := c.byUser[userID]; ok {
		ttl := identityTTL
		if e.err != nil {
			ttl = failureTTL
		}
		if now.Sub(e.at) < ttl {
			c.mu.Unlock()
			return e.id, e.err
		}
	}
	c.mu.Unlock()

	id, err := b.lookupIdentity(ctx, api, userID)
	// Remember answers, and definite refusals (IdentityError); don't
	// remember trouble reaching Slack or Tailscale.
	var definite *IdentityError
	if err == nil || errors.As(err, &definite) {
		c.mu.Lock()
		if c.byUser == nil {
			c.byUser = map[string]cachedIdentity{}
		}
		c.byUser[userID] = cachedIdentity{id: id, err: err, at: now}
		c.mu.Unlock()
	}
	return id, err
}

func (b *Bot) lookupIdentity(ctx context.Context, api slack.API, userID string) (jit.Identity, error) {
	u, err := api.UserInfo(ctx, userID)
	if err != nil {
		return jit.Identity{}, fmt.Errorf("looking up your Slack account: %w", err)
	}
	if problem := b.userProblem(u); problem != "" {
		return jit.Identity{}, &IdentityError{Msg: problem}
	}
	login := strings.ToLower(strings.TrimSpace(u.Profile.Email))
	devices, err := b.Svc.UserDevices(ctx, login)
	if err != nil {
		return jit.Identity{}, fmt.Errorf("checking that %s is on the tailnet: %w", login, err)
	}
	if len(devices) == 0 {
		return jit.Identity{}, &IdentityError{Msg: fmt.Sprintf("%s has no device on the tailnet; Slack users act in JIT access as their Tailscale login, so log in to Tailscale as %s first", login, login)}
	}
	return jit.Identity{
		Login:       login,
		DisplayName: u.RealName,
		Via:         jit.ViaSlack,
		SlackUser:   cmp.Or(u.TeamID, "?") + "/" + u.ID,
	}, nil
}

// userProblem says why u cannot act in jitd, or "".
func (b *Bot) userProblem(u slack.User) string {
	email := strings.TrimSpace(u.Profile.Email)
	switch {
	case u.Deleted:
		return "this Slack account is deactivated"
	case u.IsBot:
		return "bots can't act on access requests"
	case u.IsRestricted || u.IsUltraRestricted:
		return "guest accounts can't act on access requests"
	case email == "":
		return "your Slack account has no email address, so it can't be matched to a Tailscale login"
	case !u.IsEmailConfirmed:
		return "your Slack email address is not confirmed, so it can't be matched to a Tailscale login"
	}
	set := b.settingsCopy()
	if set.TeamID != "" && u.TeamID != "" && u.TeamID != set.TeamID {
		return "your Slack account belongs to another workspace (a shared channel); only members of " + cmp.Or(set.TeamName, "this workspace") + " can act on access requests"
	}
	allowed := set.AllowedDomains
	if !slices.Contains(allowed, emailDomain(email)) {
		return fmt.Sprintf("your Slack email (%s) is not in a domain allowed for JIT access (%s)", email, strings.Join(allowed, ", "))
	}
	return ""
}

// slackUser finds the Slack account of a Tailscale login, by email.
func (b *Bot) slackUser(ctx context.Context, api slack.API, login string) (slack.User, error) {
	key := strings.ToLower(login)
	now := b.now()
	c := &b.ids
	c.mu.Lock()
	if e, ok := c.byLogin[key]; ok {
		ttl := identityTTL
		if e.err != nil {
			ttl = failureTTL
		}
		if now.Sub(e.at) < ttl {
			c.mu.Unlock()
			return e.user, e.err
		}
	}
	c.mu.Unlock()
	u, err := api.LookupUserByEmail(ctx, login)
	if err != nil && slack.ErrorCode(err) == "" {
		return u, err // network trouble: don't remember it
	}
	c.mu.Lock()
	if c.byLogin == nil {
		c.byLogin = map[string]cachedUser{}
	}
	c.byLogin[key] = cachedUser{user: u, err: err, at: now}
	c.mu.Unlock()
	return u, err
}
