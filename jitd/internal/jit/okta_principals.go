package jit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// Okta group principals.
//
// "okta:<group>" names everyone in an Okta group, by its exact name or its
// ID (00g…), as a requester, an approver or an admin. A person matches when
// their Okta user (found by Tailscale login, then by email, as for Okta
// grants) is a member of the group. Any group type counts here, including
// groups pushed from a directory, since jitd only reads them.
//
// Lookups are cached for OktaCacheTTL. A failed lookup counts as no match
// (fail closed) and is logged.

// OktaPrefix starts an Okta group principal.
const OktaPrefix = "okta:"

// IsOkta reports whether p names an Okta group.
func (p Principal) IsOkta() bool { return strings.HasPrefix(string(p), OktaPrefix) }

// OktaRef is the group name or ID of an okta: principal.
func (p Principal) OktaRef() string { return strings.TrimPrefix(string(p), OktaPrefix) }

// OktaCacheTTL is how long Okta membership lookups are reused.
const OktaCacheTTL = time.Minute

// oktaErrTTL is how long a failed lookup is remembered, so a broken token
// does not mean one API call per page view.
const oktaErrTTL = 10 * time.Second

type cachedGroups struct {
	groups []okta.Group
	err    error
	at     time.Time
}

type cachedMembers struct {
	keys []string
	err  error
	at   time.Time
}

// oktaCache caches, per login, the user's groups, and, per group reference,
// the member keys. The zero value is ready to use.
type oktaCache struct {
	mu      sync.Mutex
	users   map[string]cachedGroups
	members map[string]cachedMembers
}

// oktaUserGroups returns the Okta groups of the person with this Tailscale
// login. A login with no Okta user has no groups (and no error).
func (s *Service) oktaUserGroups(ctx context.Context, login string) ([]okta.Group, error) {
	key := strings.ToLower(login)
	now := s.now()
	c := &s.ocache
	c.mu.Lock()
	if e, ok := c.users[key]; ok && fresh(e.at, e.err, now) {
		c.mu.Unlock()
		return e.groups, e.err
	}
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var groups []okta.Group
	u, err := s.Okta.FindUser(ctx, login)
	switch {
	case errors.Is(err, okta.ErrNotFound):
		err = nil // no Okta user: in no groups
	case err == nil:
		groups, err = s.Okta.UserGroups(ctx, u.ID)
	}
	c.mu.Lock()
	if c.users == nil {
		c.users = map[string]cachedGroups{}
	}
	c.users[key] = cachedGroups{groups: groups, err: err, at: now}
	c.mu.Unlock()
	return groups, err
}

// oktaGroupMemberKeys returns the member keys (lowercased emails) of the
// group ref names.
func (s *Service) oktaGroupMemberKeys(ctx context.Context, ref string) ([]string, error) {
	now := s.now()
	c := &s.ocache
	c.mu.Lock()
	if e, ok := c.members[ref]; ok && fresh(e.at, e.err, now) {
		c.mu.Unlock()
		return e.keys, e.err
	}
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	var keys []string
	g, err := s.Okta.FindGroup(ctx, ref)
	if err == nil && !s.readAllowed(g.ID, g.Name()) {
		err = fmt.Errorf("Okta group %q is not on jitd's read allowlist (%s)", ref, EnvOktaReadAllowlist)
	}
	if err == nil {
		var us []okta.User
		us, err = s.Okta.GroupMembers(ctx, g.ID)
		for _, u := range us {
			if u.Status == "" || u.Status == "ACTIVE" || u.Status == "PASSWORD_EXPIRED" || u.Status == "RECOVERY" {
				keys = append(keys, u.Key())
			}
		}
	}
	c.mu.Lock()
	if c.members == nil {
		c.members = map[string]cachedMembers{}
	}
	c.members[ref] = cachedMembers{keys: keys, err: err, at: now}
	c.mu.Unlock()
	return keys, err
}

func fresh(at time.Time, err error, now time.Time) bool {
	ttl := OktaCacheTTL
	if err != nil {
		ttl = oktaErrTTL
	}
	return now.Sub(at) < ttl && !now.Before(at)
}

// matchesOkta reports whether id is in the Okta group p names.
func (s *Service) matchesOkta(ctx context.Context, p Principal, id Identity) bool {
	if id.Tagged() || id.Login == "" || !s.oktaEnabled() {
		return false
	}
	groups, err := s.oktaUserGroups(ctx, id.Login)
	if err != nil {
		s.Log.Error("cannot read Okta group membership; okta: principals will not match", "login", id.Login, "err", err)
		return false
	}
	ref := p.OktaRef()
	for _, g := range groups {
		if g.Matches(ref) {
			if !s.readAllowed(g.ID, g.Name()) {
				s.Log.Warn("okta: principal names a group outside the read allowlist; it matches nobody", "group", ref)
				return false
			}
			return true
		}
	}
	return false
}

// checkOktaPrincipals makes sure every okta: principal of w names one
// existing Okta group, so a typo does not save a flow nobody can use.
func (s *Service) checkOktaPrincipals(ctx context.Context, w *Workflow) error {
	var refs []string
	for _, p := range append(append([]Principal{}, w.Requesters...), w.Approvers...) {
		if p.IsOkta() {
			refs = append(refs, p.OktaRef())
		}
	}
	if len(refs) == 0 {
		return nil
	}
	if !s.oktaEnabled() {
		return conflict("this approval flow names okta: principals, but Okta is not configured: set OKTA_ORG_URL and either OKTA_API_TOKEN or OKTA_CLIENT_ID and OKTA_PRIVATE_KEY in jitd's env file")
	}
	actx, cancel := apiContext(ctx)
	defer cancel()
	for _, ref := range refs {
		g, err := s.Okta.FindGroup(actx, ref)
		switch {
		case errors.Is(err, okta.ErrNotFound):
			return badRequest("Okta group %q not found (okta: takes the exact group name or its ID)", ref)
		case err != nil:
			return apiFailed("looking up Okta group %q: %v", ref, err)
		case !s.readAllowed(g.ID, g.Name()):
			return forbidden("Okta group %q is not on jitd's read allowlist (%s)", ref, EnvOktaReadAllowlist)
		}
	}
	return nil
}
