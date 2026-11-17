package jit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Keeping the systems that have groups (Okta) and jitd's record of them in
// step.
//
// Every expiry tick, after the service lock is released, jitd does this
// for each group provider:
//
//   - takes back the memberships of approvals that did not finish (jitd
//     stopped halfway, or the take-back failed at the time);
//   - removes the memberships of ended requests, retrying the ones that
//     failed before;
//   - tells the admins, once, about a removal that has kept failing for
//     OktaAlertAfter;
//   - now and then compares the memberships of running requests with the
//     provider, and notes the ones somebody removed there;
//   - now and then checks that its credentials still work.
//
// It only ever touches memberships it has a record of adding. The first
// three run even while the provider is off (no credentials, or unusable
// ones): they then fail, and that is recorded and reported, where skipping
// them would leave memberships in place with nobody told.

const (
	// groupTimeout bounds a provider's calls of one expiry tick.
	groupTimeout = 30 * time.Second
	// DefaultGroupAlertAfter is how long a removal may keep failing before
	// the admins are told.
	DefaultGroupAlertAfter = 5 * time.Minute
	// DefaultOktaAlertAfter is DefaultGroupAlertAfter.
	DefaultOktaAlertAfter = DefaultGroupAlertAfter
	// groupVerifyEvery is how often a running request's memberships are
	// compared with the provider.
	groupVerifyEvery = 10 * time.Minute
	// groupCheckEvery is how often a provider's credentials are checked
	// while they work, and groupRecheckEvery while they do not.
	groupCheckEvery   = time.Hour
	groupRecheckEvery = 5 * time.Minute
	// groupCheckTimeout bounds that check.
	groupCheckTimeout = 15 * time.Second
)

// groupStepContext gives one step of the upkeep its own time, counted from
// the moment it holds groupMu. The tick's context only decides whether
// another step is started: a step that waited behind a slow approval must
// not then fail, and be recorded as a failed removal, because the wait used
// up the time.
func groupStepContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), groupTimeout)
}

// groupUpkeep is the group providers' part of the expiry tick. The caller
// must not hold mu.
func (s *Service) groupUpkeep(ctx context.Context) {
	for _, p := range s.providers() {
		if p.client == nil {
			continue
		}
		s.dropIntents(ctx, p)
		s.releaseDue(ctx, p)
		s.alertStuck(p)
		if p.on() {
			s.verifyGroups(ctx, p)
		}
		s.checkProvider(ctx, p)
	}
}

// owed counts the requests with memberships of p's kind that jitd still
// has to look after: running grants, removals not done yet, approvals that
// did not finish.
func (s *Service) owed(p *groupProvider) int {
	now := s.now()
	n := 0
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if p.intent(r) != nil || p.pendingRemoval(r) || p.running(r, now) {
				n++
			}
		}
	})
	return n
}

// dropIntents takes back the memberships of approvals that did not finish.
// An approval (grantOutsideLock) holds groupMu from before it writes an
// intent until the approval is saved or taken back, so an intent seen
// under groupMu belongs to no approval in flight.
func (s *Service) dropIntents(ctx context.Context, p *groupProvider) {
	var ids []string
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if p.intent(r) != nil {
				ids = append(ids, r.ID)
			}
		}
	})
	slices.Sort(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		s.dropIntent(ctx, p, id)
	}
}

func (s *Service) dropIntent(ctx context.Context, p *groupProvider, id string) {
	s.groupMu.Lock()
	defer s.groupMu.Unlock()
	ctx, cancel := groupStepContext(ctx)
	defer cancel()
	r := s.Request(id)
	if r == nil || p.intent(r) == nil {
		return
	}
	a := p.intent(r)
	keep := s.kept(p, a.UserID, r.ID)
	var left []string
	var errs []error
	for _, g := range a.Groups {
		if keep[g] {
			continue
		}
		// jitd may have stopped before it added the user, or after, or
		// the add may have failed without the provider saying whether it
		// was applied. The user was not in the group when the intent was
		// written, so taking them out puts things back either way. (The
		// one case this gets wrong: somebody else added the user between
		// then and now. jitd cannot tell that from its own add.)
		if err := p.client.Remove(ctx, g, a.UserID); err != nil {
			left = append(left, g)
			errs = append(errs, fmt.Errorf("removing from %s group %s: %w", p.label, p.labelOf(r, g), err))
		}
	}
	why := ""
	if err := errors.Join(errs...); err != nil {
		why = err.Error()
		if why != a.Error {
			s.Log.Error("an approval did not finish and its "+p.label+" memberships could not be taken back; will retry", "id", id, "user", a.Login, "err", err)
		}
	} else {
		s.Log.Warn("an approval did not finish; its "+p.label+" memberships were taken back", "id", id, "user", a.Login, "groups", strings.Join(p.labels(r, a.Groups), ", "))
	}
	s.settleIntent(p, id, left, why)
}

// alertStuck marks the ended requests whose removal from p's groups has
// kept failing for OktaAlertAfter, and tells the Notifier about each, once.
func (s *Service) alertStuck(p *groupProvider) {
	after := s.OktaAlertAfter
	if after <= 0 {
		after = DefaultGroupAlertAfter
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var stuck []*AccessRequest
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		stuck = nil
		for _, r := range d.Requests {
			if !p.pendingRemoval(r) {
				continue
			}
			g := p.granted(r)
			if g.AlertedAt != nil || g.FailingSince == nil || now.Sub(*g.FailingSince) < after {
				continue
			}
			at := now
			g.AlertedAt = &at
			stuck = append(stuck, clone(r))
		}
		return len(stuck) > 0, nil
	})
	if err != nil {
		s.Log.Error("saving "+p.label+" alerts", "err", err)
		return
	}
	for _, r := range stuck {
		g := p.granted(r)
		s.Log.Error("access ended but the "+p.label+" group memberships are still in place; jitd keeps retrying", "id", r.ID, "user", g.Login,
			"groups", strings.Join(p.labels(r, g.Added), ", "), "failing_since", g.FailingSince.Format(time.RFC3339), "err", g.Error)
		s.emit(r, Event{Type: p.stuck, Actor: "system", At: now})
	}
}

// verifyGroups compares the memberships of running requests with the
// provider, for the users not looked at in the last groupVerifyEvery. It
// only notes what is missing: someone with rights there took the user out,
// and jitd does not overrule them.
func (s *Service) verifyGroups(ctx context.Context, p *groupProvider) {
	now := s.now()
	last := map[string]time.Time{} // user ID -> the oldest check among their requests
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if !p.running(r, now) {
				continue
			}
			g := p.granted(r)
			var at time.Time
			if g.CheckedAt != nil {
				at = *g.CheckedAt
			}
			if cur, ok := last[g.UserID]; !ok || at.Before(cur) {
				last[g.UserID] = at
			}
		}
	})
	var users []string
	for u, at := range last {
		if now.Sub(at) >= groupVerifyEvery {
			users = append(users, u)
		}
	}
	slices.SortFunc(users, func(a, b string) int {
		if c := last[a].Compare(last[b]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	if len(users) > groupBatch {
		users = users[:groupBatch]
	}
	for _, u := range users {
		if ctx.Err() != nil {
			return
		}
		s.verifyMember(ctx, p, u)
	}
}

func (s *Service) verifyMember(ctx context.Context, p *groupProvider, userID string) {
	s.groupMu.Lock() // no grant or removal for this user while we compare
	defer s.groupMu.Unlock()
	ctx, cancel := groupStepContext(ctx)
	defer cancel()
	now := s.now()
	var ids []string // the groups jitd holds for this user
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if g := p.granted(r); p.running(r, now) && g.UserID == userID {
				for _, id := range g.Added {
					if !slices.Contains(ids, id) {
						ids = append(ids, id)
					}
				}
			}
		}
	})
	slices.Sort(ids)
	in, err := p.client.Holding(ctx, userID, ids)
	if err != nil {
		s.Log.Warn("comparing "+p.label+" group memberships with jitd's record", "user", userID, "err", err)
	}
	now = s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var lost, back []*AccessRequest
	serr := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		lost, back = nil, nil
		for _, r := range d.Requests {
			g := p.granted(r)
			if !p.running(r, now) || g.UserID != userID {
				continue
			}
			at := now
			g.CheckedAt = &at // also after a failed call: try again in groupVerifyEvery, not every tick
			if err != nil {
				continue
			}
			var missing []string
			for _, id := range g.Added {
				if !in[id] {
					missing = append(missing, id)
				}
			}
			if slices.Equal(missing, g.Missing) {
				continue
			}
			g.Missing = missing
			if len(missing) > 0 {
				lost = append(lost, clone(r))
			} else {
				back = append(back, clone(r))
			}
		}
		return len(lost)+len(back) > 0, nil
	})
	if serr != nil {
		s.Log.Error("saving the "+p.label+" comparison", "user", userID, "err", serr)
		return
	}
	for _, r := range lost {
		g := p.granted(r)
		s.Log.Warn("the "+p.label+" user was taken out of a group while the access is still running; jitd does not add them back", "id", r.ID, "user", g.Login,
			"groups", strings.Join(p.labels(r, g.Missing), ", "))
	}
	for _, r := range back {
		s.Log.Info("the "+p.label+" user is back in every group of the request", "id", r.ID, "user", p.granted(r).Login)
	}
}

// groupHealth is the outcome of the last check of a provider's credentials.
type groupHealth struct {
	mu    sync.Mutex
	at    time.Time
	err   string
	cause error // the error err is the text of
	off   bool  // the provider was off with memberships still to look after, and that was logged
}

// GroupState is how jitd's use of a group provider stands, for its page.
type GroupState struct {
	Enabled   bool      // credentials are set and usable (the provider may still refuse them: Err)
	Off       string    // why not, when they are not
	CheckedAt time.Time // when jitd last tried the credentials; zero if not yet
	Err       error     // what that try came back with; nil when it worked
	Held      int       // requests whose memberships jitd still has to look after
}

func (s *Service) groupState(p *groupProvider) GroupState {
	if p.client == nil {
		return GroupState{Off: "this build of jitd has no " + p.label + " client"}
	}
	st := GroupState{Enabled: p.on(), Held: s.owed(p)}
	if !st.Enabled {
		st.Off = p.whyOff()
		return st
	}
	h := p.health
	h.mu.Lock()
	defer h.mu.Unlock()
	st.CheckedAt = h.at
	if h.err != "" {
		st.Err = h.cause
	}
	return st
}

// groupCheckNow tries p's credentials now rather than at the next check
// that is due, and returns what the provider said.
func (s *Service) groupCheckNow(ctx context.Context, p *groupProvider) error {
	if p.client == nil {
		return nil
	}
	h := p.health
	h.mu.Lock()
	h.at = time.Time{}
	h.mu.Unlock()
	s.checkProvider(ctx, p)
	return s.groupState(p).Err
}

// checkProvider checks, now and then, that p's credentials still work, so
// a revoked or expired one shows before the next removal needs it. (Okta
// also expires API tokens that go unused for 30 days; this keeps jitd's in
// use.)
func (s *Service) checkProvider(ctx context.Context, p *groupProvider) {
	now := s.now()
	h := p.health
	if !p.on() {
		// There are no credentials to check. If memberships are waiting
		// on them, say so (groupProblems tells the admins).
		owed := s.owed(p)
		h.mu.Lock()
		was := h.off
		h.off, h.at, h.err, h.cause = owed > 0, time.Time{}, "", nil
		h.mu.Unlock()
		if owed > 0 && !was {
			s.Log.Error(p.label+" is off while jitd still has "+p.label+" group memberships to look after; they stay in place until "+p.label+" is configured again",
				"requests", owed, "err", p.whyOff())
		}
		return
	}
	h.mu.Lock()
	at, was := h.at, h.err
	h.off = false
	h.mu.Unlock()
	every := groupCheckEvery
	if was != "" {
		every = groupRecheckEvery
	}
	if !at.IsZero() && now.Sub(at) < every {
		return
	}
	// The check gets its own time: the tick's may have run out waiting for
	// an approval to finish, and that is not the provider failing.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), groupCheckTimeout)
	defer cancel()
	msg := ""
	err := p.client.Check(cctx)
	if err != nil {
		msg = err.Error()
	}
	h.mu.Lock()
	h.at, h.err, h.cause = now, msg, err
	h.mu.Unlock()
	switch {
	case msg != "" && msg != was:
		s.Log.Error("jitd cannot use the "+p.label+" API; memberships cannot be added or removed until this is fixed", "err", msg)
	case msg == "" && was != "":
		s.Log.Info("the " + p.label + " API works again")
	}
}

// GroupProblem is something about a group provider an admin should look at.
type GroupProblem struct {
	RequestID string // the request it is about; empty for the connection itself
	Text      string
}

// groupProblems lists what an admin should know about p right now: it is
// off while memberships jitd added are still in place, its settings cannot
// be read, the credentials do not work, a removal is stuck, or an
// unfinished approval could not be taken back. Empty when all is well.
func (s *Service) groupProblems(p *groupProvider) []GroupProblem {
	if p.client == nil {
		return nil
	}
	var out []GroupProblem
	if !p.on() {
		n := s.owed(p)
		if n == 0 {
			return nil // the provider is not in use
		}
		out = append(out, GroupProblem{Text: fmt.Sprintf("%s is off, but %d request(s) still have %s group memberships that jitd added. jitd cannot remove them until %s is configured again: %s", p.label, n, p.label, p.label, p.whyOff())})
	} else {
		if why := p.stale(); why != "" {
			out = append(out, GroupProblem{Text: "jitd cannot read its " + p.label + " settings and carries on with the ones it read last, allowlists included: " + why})
		}
		h := p.health
		h.mu.Lock()
		if h.err != "" {
			out = append(out, GroupProblem{Text: "jitd cannot use the " + p.label + " API, so it cannot add or remove group memberships: " + h.err})
		}
		h.mu.Unlock()
	}
	failed := func(r *AccessRequest) bool { a := p.intent(r); return a != nil && a.Error != "" }
	var rs []*AccessRequest
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if p.stuckOn(r) || failed(r) {
				rs = append(rs, clone(r))
			}
		}
	})
	slices.SortFunc(rs, func(a, b *AccessRequest) int { return strings.Compare(a.ID, b.ID) })
	for _, r := range rs {
		if p.stuckOn(r) {
			g := p.granted(r)
			out = append(out, GroupProblem{RequestID: r.ID, Text: fmt.Sprintf("%s is still in %s although the access through %q has ended. Removing keeps failing: %s",
				g.Login, strings.Join(p.labels(r, g.Added), ", "), r.WorkflowName, g.Error)})
		}
		if failed(r) {
			a := p.intent(r)
			out = append(out, GroupProblem{RequestID: r.ID, Text: fmt.Sprintf("an approval through %q did not finish and may have left %s in %s. Taking that back keeps failing: %s",
				r.WorkflowName, a.Login, strings.Join(p.labels(r, a.Groups), ", "), a.Error)})
		}
	}
	return out
}

// AdminLogins lists the admins by login, as ApproverLogins does for a flow's
// approvers.
func (s *Service) AdminLogins(ctx context.Context) ([]string, error) {
	return s.ApproverLogins(ctx, &Workflow{Approvers: s.Admins})
}
