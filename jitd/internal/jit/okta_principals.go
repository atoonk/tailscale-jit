package jit

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// OktaRef is the group name or ID of an okta: principal, without the
// space people leave after the colon.
func (p Principal) OktaRef() string {
	return strings.TrimSpace(strings.TrimPrefix(string(p), OktaPrefix))
}

// OktaCacheTTL is how long Okta membership lookups are reused.
const OktaCacheTTL = time.Minute

// oktaErrTTL is how long a failed lookup is remembered, so a broken token
// or an Okta that does not answer does not mean one API call (and one
// timeout) per page view. It is longer than the lookup timeout, so lookups
// that queued up behind a slow one find its failure still fresh.
const oktaErrTTL = 30 * time.Second

// oktaLookupTimeout bounds one lookup.
const oktaLookupTimeout = 10 * time.Second

type cached[T any] struct {
	v   T
	err error
	at  time.Time // when the answer arrived
}

func (e cached[T]) fresh(now time.Time) bool {
	ttl := OktaCacheTTL
	if e.err != nil {
		ttl = oktaErrTTL
	}
	return now.Sub(e.at) < ttl && !now.Before(e.at)
}

// oktaCache caches, per login, the user's groups; per group reference, the
// group it names; and, per group ID, the member keys. The zero value is
// ready to use.
//
// Lookups run one at a time (fill), and after one that shows Okta itself is
// failing (no answer, a 5xx, a refused credential) every lookup fails at
// once until downUntil. Without that, a slow Okta would make each page view
// wait out its own timeout, one after the other.
type oktaCache struct {
	fill sync.Mutex // held while calling Okta; taken before mu

	mu        sync.Mutex
	users     map[string]cached[[]okta.Group]
	groups    map[string]cached[okta.Group]
	members   map[string]cached[[]string]
	downUntil time.Time
	downErr   error
}

// oktaDown reports whether err says Okta as a whole is not usable, as
// opposed to one user or group not being found.
func oktaDown(err error) bool {
	var ae *okta.APIError
	if errors.As(err, &ae) {
		return ae.Status == 401 || ae.Status == 403 || ae.Status == 429 || ae.Status >= 500
	}
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, okta.ErrUnconfigured) || errors.As(err, &ne)
}

// oktaLookup returns the cached answer for key in the map pick selects, or
// gets it with load, one lookup at a time.
func oktaLookup[T any](ctx context.Context, s *Service, pick func(*oktaCache) *map[string]cached[T], key string, load func(context.Context) (T, error)) (T, error) {
	c := &s.ocache
	have := func() (T, error, bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		now := s.now()
		if e, ok := (*pick(c))[key]; ok && e.fresh(now) {
			return e.v, e.err, true
		}
		if now.Before(c.downUntil) {
			var zero T
			return zero, c.downErr, true
		}
		return *new(T), nil, false
	}
	if v, err, ok := have(); ok {
		return v, err
	}
	c.fill.Lock()
	defer c.fill.Unlock()
	if v, err, ok := have(); ok { // whoever held fill may have got it
		return v, err
	}
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oktaLookupTimeout)
	defer cancel()
	v, err := load(lctx)
	if err != nil {
		s.Log.Error("Okta lookup failed; okta: principals that depend on it match nobody until it works", "lookup", key, "err", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := s.now() // after the call: a slow answer is not already stale
	m := pick(c)
	if *m == nil {
		*m = map[string]cached[T]{}
	}
	(*m)[key] = cached[T]{v: v, err: err, at: now}
	if oktaDown(err) {
		c.downUntil, c.downErr = now.Add(oktaErrTTL), err
	}
	return v, err
}

// oktaUserGroups returns the Okta groups of the person with this Tailscale
// login. A login with no Okta user has no groups (and no error), and
// neither has a user who is suspended or deactivated: Okta keeps their
// memberships, but they must not count as an approver, a requester or an
// admin.
func (s *Service) oktaUserGroups(ctx context.Context, login string) ([]okta.Group, error) {
	return oktaLookup(ctx, s, func(c *oktaCache) *map[string]cached[[]okta.Group] { return &c.users }, strings.ToLower(login),
		func(ctx context.Context) ([]okta.Group, error) {
			u, err := s.Okta.FindUser(ctx, login)
			switch {
			case errors.Is(err, okta.ErrNotFound):
				return nil, nil
			case err != nil:
				return nil, err
			case !u.Active():
				return nil, nil
			}
			return s.Okta.UserGroups(ctx, u.ID)
		})
}

// oktaGroup returns the one Okta group ref names, by ID or exact name, if
// it is on the read allowlist. A name that more than one group has is an
// error: jitd will not guess which was meant.
func (s *Service) oktaGroup(ctx context.Context, ref string) (okta.Group, error) {
	g, err := oktaLookup(ctx, s, func(c *oktaCache) *map[string]cached[okta.Group] { return &c.groups }, ref,
		func(ctx context.Context) (okta.Group, error) { return s.Okta.FindGroup(ctx, ref) })
	if err != nil {
		return okta.Group{}, err
	}
	if !s.readAllowed(g.ID, g.Name()) {
		return okta.Group{}, fmt.Errorf("Okta group %q is not on jitd's read allowlist (%s)", ref, EnvOktaReadAllowlist)
	}
	return g, nil
}

// oktaGroupMemberKeys returns the member keys (lowercased emails) of the
// group ref names.
func (s *Service) oktaGroupMemberKeys(ctx context.Context, ref string) ([]string, error) {
	g, err := s.oktaGroup(ctx, ref)
	if err != nil {
		return nil, err
	}
	return oktaLookup(ctx, s, func(c *oktaCache) *map[string]cached[[]string] { return &c.members }, g.ID,
		func(ctx context.Context) ([]string, error) {
			us, err := s.Okta.GroupMembers(ctx, g.ID)
			if err != nil {
				return nil, err
			}
			var keys []string
			for _, u := range us {
				if u.Active() {
					keys = append(keys, u.Key())
				}
			}
			return keys, nil
		})
}

// matchesOkta reports whether id is in the Okta group p names. The
// reference is resolved to one group first and the person's groups are then
// compared by ID, so a group that merely carries the same name as another
// one (or a name that looks like another group's ID) confers nothing.
func (s *Service) matchesOkta(ctx context.Context, p Principal, id Identity) bool {
	if id.Tagged() || id.Login == "" || !s.oktaEnabled() {
		return false
	}
	g, err := s.oktaGroup(ctx, p.OktaRef())
	if err != nil {
		return false // logged when the lookup failed
	}
	groups, err := s.oktaUserGroups(ctx, id.Login)
	if err != nil {
		return false
	}
	for _, ug := range groups {
		if ug.ID == g.ID {
			return true
		}
	}
	return false
}

// CheckOktaPrincipal reports why the okta: principal p cannot be used right
// now (the group is not found, the name is ambiguous, it is off the read
// allowlist, Okta does not answer), or nil. It is for start-up checks of
// principals that no flow form validates, such as -admins.
func (s *Service) CheckOktaPrincipal(ctx context.Context, p Principal) error {
	if !p.IsOkta() {
		return nil
	}
	if !s.oktaEnabled() {
		return errors.New("Okta is not configured")
	}
	_, err := s.oktaGroup(ctx, p.OktaRef())
	return err
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
		return conflict("this approval flow names okta: principals, but Okta is not configured: an admin can set it up on jitd's Okta page (or set OKTA_ORG_URL and either OKTA_API_TOKEN or OKTA_CLIENT_ID and OKTA_PRIVATE_KEY in jitd's env file)")
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
