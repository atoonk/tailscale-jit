package jit

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// PolicyCache keeps a copy of the tailnet policy file, read through the
// Tailscale API: its groups resolve group: principals, and its postures and
// grants feed the policy check and the snippet.
type PolicyCache struct {
	TS  tsapi.Client
	TTL time.Duration
	Log *slog.Logger
	Now func() time.Time

	mu      sync.Mutex
	policy  *tsapi.Policy
	err     error     // last fetch error, served until retryAt
	fetched time.Time // when policy was fetched
	retryAt time.Time // after a failed fetch, when to try again
	fetch   sync.Mutex
}

// failureBackoff is how long a failed policy fetch is remembered, so an API
// outage costs one timeout per interval instead of one per caller.
const failureBackoff = 15 * time.Second

// Groups returns the policy file's groups (see Policy).
func (g *PolicyCache) Groups(ctx context.Context) (map[string][]string, error) {
	p, err := g.Policy(ctx)
	if err != nil {
		return nil, err
	}
	if p.Groups == nil {
		return map[string][]string{}, nil
	}
	return p.Groups, nil
}

// cached returns the policy if it can be served without a fetch: fresh, or
// within the backoff after a failed fetch (then the stale copy, or the
// error if there is none).
func (g *PolicyCache) cached(now time.Time) (*tsapi.Policy, error, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.policy != nil && now.Sub(g.fetched) < g.TTL {
		return g.policy, nil, true
	}
	if now.Before(g.retryAt) {
		if g.policy != nil {
			return g.policy, nil, true
		}
		return nil, g.err, true
	}
	return nil, nil, false
}

// Policy returns the cached policy file. On a fetch error it serves the
// stale copy if there is one, and does not try again for failureBackoff.
// Only one fetch runs at a time; callers arriving meanwhile get its result.
// The fetch runs with its own bounded context, not the caller's: a browser
// tab closing must not turn into a failed lookup for whoever else waited.
func (g *PolicyCache) Policy(ctx context.Context) (*tsapi.Policy, error) {
	now := g.now()
	if p, err, ok := g.cached(now); ok {
		return p, err
	}
	// One fetch at a time. While it runs, others get the stale copy if
	// there is one, rather than wait up to the fetch timeout.
	if !g.fetch.TryLock() {
		g.mu.Lock()
		stale := g.policy
		g.mu.Unlock()
		if stale != nil {
			return stale, nil
		}
		g.fetch.Lock()
	}
	defer g.fetch.Unlock()
	if p, err, ok := g.cached(g.now()); ok { // fetched while we waited
		return p, err
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	p, err := g.TS.GetPolicy(fctx)

	g.mu.Lock()
	defer g.mu.Unlock()
	now = g.now()
	if err != nil {
		g.err, g.retryAt = err, now.Add(failureBackoff)
		if g.policy != nil {
			g.Log.Warn("policy fetch failed; using the cached policy", "err", err)
			return g.policy, nil
		}
		return nil, err
	}
	g.policy, g.fetched, g.err, g.retryAt = &p, now, nil, time.Time{}
	return g.policy, nil
}

func (g *PolicyCache) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// matches reports whether id is covered by any principal. Group principals are
// only resolved when needed; a failed group lookup counts as no match and is
// logged.
func (s *Service) matches(ctx context.Context, ps []Principal, id Identity) bool {
	var groups map[string][]string
	var groupsErr error
	var loaded bool
	for _, p := range ps {
		name := string(p)
		switch {
		case p == AutogroupMember:
			if !id.Tagged() && strings.Contains(id.Login, "@") {
				return true
			}
		case strings.HasPrefix(name, "tag:"):
			if slices.Contains(id.Tags, name) {
				return true
			}
		case strings.HasPrefix(name, "group:"):
			if id.Tagged() || s.PolicyCache == nil {
				continue
			}
			if !loaded {
				groups, groupsErr = s.PolicyCache.Groups(ctx)
				loaded = true
				if groupsErr != nil {
					s.Log.Error("cannot resolve policy groups; group principals will not match", "err", groupsErr)
				}
			}
			for _, m := range groups[name] {
				if strings.EqualFold(m, id.Login) {
					return true
				}
			}
		default:
			if !id.Tagged() && strings.EqualFold(name, id.Login) {
				return true
			}
		}
	}
	return false
}
