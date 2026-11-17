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

// Keeping Okta and jitd's record of it in step.
//
// Every expiry tick, after the service lock is released, jitd:
//
//   - takes back the memberships of approvals that did not finish (jitd
//     stopped halfway, or the take-back failed at the time);
//   - removes the memberships of ended requests, retrying the ones that
//     failed before;
//   - tells the admins, once, about a removal that has kept failing for
//     OktaAlertAfter;
//   - now and then compares the memberships of running requests with Okta,
//     and notes the ones somebody removed there;
//   - now and then checks that its Okta credentials still work.
//
// It only ever touches memberships it has a record of adding. The first
// three run even while Okta is off (no credentials, or unusable ones): they
// then fail, and that is recorded and reported, where skipping them would
// leave memberships in place with nobody told.

const (
	// oktaTimeout bounds the Okta calls of one expiry tick.
	oktaTimeout = 30 * time.Second
	// DefaultOktaAlertAfter is how long a removal may keep failing before
	// the admins are told.
	DefaultOktaAlertAfter = 5 * time.Minute
	// oktaVerifyEvery is how often a running request's memberships are
	// compared with Okta.
	oktaVerifyEvery = 10 * time.Minute
	// oktaCheckEvery is how often the Okta credentials are checked while
	// they work, and oktaRecheckEvery while they do not.
	oktaCheckEvery   = time.Hour
	oktaRecheckEvery = 5 * time.Minute
	// oktaCheckTimeout bounds that check.
	oktaCheckTimeout = 15 * time.Second
)

// oktaUpkeep is the Okta part of the expiry tick. The caller must not hold mu.
// oktaStepContext gives one step of the upkeep its own time, counted from
// the moment it holds oktaMu. The tick's context only decides whether
// another step is started: a step that waited behind a slow approval must
// not then fail, and be recorded as a failed removal, because the wait used
// up the time.
func oktaStepContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), oktaTimeout)
}

func (s *Service) oktaUpkeep(ctx context.Context) {
	if s.Okta == nil {
		return
	}
	s.dropOktaIntents(ctx)
	s.releaseOktaDue(ctx)
	s.alertOktaStuck()
	if s.oktaEnabled() {
		s.verifyOkta(ctx)
	}
	s.checkOkta(ctx)
}

// oktaOwed counts the requests with Okta memberships jitd still has to look
// after: running grants, removals not done yet, approvals that did not
// finish.
func (s *Service) oktaOwed() int {
	now := s.now()
	n := 0
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.OktaAdding != nil || r.oktaPendingRemoval() || r.oktaRunning(now) {
				n++
			}
		}
	})
	return n
}

// oktaWhyOff says why Okta is off, for people.
func (s *Service) oktaWhyOff() string {
	if e, ok := s.Okta.(interface{ Err() error }); ok {
		if err := e.Err(); err != nil {
			return err.Error()
		}
	}
	return "Okta is not configured"
}

// dropOktaIntents takes back the memberships of approvals that did not
// finish. An approval (grantOutsideLock) holds oktaMu from before it writes
// an intent until the approval is saved or taken back, so an intent seen
// under oktaMu belongs to no approval in flight.
func (s *Service) dropOktaIntents(ctx context.Context) {
	var ids []string
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.OktaAdding != nil {
				ids = append(ids, r.ID)
			}
		}
	})
	slices.Sort(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		s.dropOktaIntent(ctx, id)
	}
}

func (s *Service) dropOktaIntent(ctx context.Context, id string) {
	s.oktaMu.Lock()
	defer s.oktaMu.Unlock()
	ctx, cancel := oktaStepContext(ctx)
	defer cancel()
	r := s.Request(id)
	if r == nil || r.OktaAdding == nil {
		return
	}
	a := r.OktaAdding
	keep := s.oktaKept(a.UserID, r.ID)
	var left []string
	var errs []error
	for _, g := range a.Groups {
		if keep[g] {
			continue
		}
		// jitd may have stopped before it added the user, or after, or
		// the add may have failed without Okta saying whether it was
		// applied. The user was not in the group when the intent was
		// written, so taking them out puts things back either way. (The
		// one case this gets wrong: somebody else added the user between
		// then and now. jitd cannot tell that from its own add.)
		if err := s.Okta.RemoveMember(ctx, g, a.UserID); err != nil {
			left = append(left, g)
			errs = append(errs, fmt.Errorf("removing from Okta group %s: %w", s.oktaLabel(r, g), err))
		}
	}
	why := ""
	if err := errors.Join(errs...); err != nil {
		why = err.Error()
		if why != a.Error {
			s.Log.Error("an approval did not finish and its Okta memberships could not be taken back; will retry", "id", id, "user", a.Login, "err", err)
		}
	} else {
		s.Log.Warn("an approval did not finish; its Okta memberships were taken back", "id", id, "user", a.Login, "groups", strings.Join(r.oktaLabels(a.Groups), ", "))
	}
	s.settleOktaIntent(id, left, why)
}

// alertOktaStuck marks the ended requests whose Okta removal has kept
// failing for OktaAlertAfter, and tells the Notifier about each, once.
func (s *Service) alertOktaStuck() {
	after := s.OktaAlertAfter
	if after <= 0 {
		after = DefaultOktaAlertAfter
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var stuck []*AccessRequest
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		stuck = nil
		for _, r := range d.Requests {
			if !r.oktaPendingRemoval() || r.Okta.AlertedAt != nil || r.Okta.FailingSince == nil || now.Sub(*r.Okta.FailingSince) < after {
				continue
			}
			at := now
			r.Okta.AlertedAt = &at
			stuck = append(stuck, clone(r))
		}
		return len(stuck) > 0, nil
	})
	if err != nil {
		s.Log.Error("saving Okta alerts", "err", err)
		return
	}
	for _, r := range stuck {
		s.Log.Error("access ended but the Okta group memberships are still in place; jitd keeps retrying", "id", r.ID, "user", r.Okta.Login,
			"groups", strings.Join(r.OktaAddedLabels(), ", "), "failing_since", r.Okta.FailingSince.Format(time.RFC3339), "err", r.Okta.Error)
		s.emit(r, Event{Type: EventOktaStuck, Actor: "system", At: now})
	}
}

// verifyOkta compares the memberships of running requests with Okta, one
// call per user, for the users not looked at in the last oktaVerifyEvery.
// It only notes what is missing: someone with rights in Okta took the user
// out, and jitd does not overrule them.
func (s *Service) verifyOkta(ctx context.Context) {
	now := s.now()
	last := map[string]time.Time{} // user ID -> the oldest check among their requests
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if !r.oktaRunning(now) {
				continue
			}
			var at time.Time
			if r.Okta.CheckedAt != nil {
				at = *r.Okta.CheckedAt
			}
			if cur, ok := last[r.Okta.UserID]; !ok || at.Before(cur) {
				last[r.Okta.UserID] = at
			}
		}
	})
	var users []string
	for u, at := range last {
		if now.Sub(at) >= oktaVerifyEvery {
			users = append(users, u)
		}
	}
	slices.SortFunc(users, func(a, b string) int {
		if c := last[a].Compare(last[b]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	if len(users) > oktaBatch {
		users = users[:oktaBatch]
	}
	for _, u := range users {
		if ctx.Err() != nil {
			return
		}
		s.verifyOktaUser(ctx, u)
	}
}

// oktaRunning reports whether r's access is running with memberships jitd
// added.
func (r *AccessRequest) oktaRunning(now time.Time) bool {
	return r.Status == StatusApproved && r.ExpiresAt != nil && r.ExpiresAt.After(now) &&
		r.Okta != nil && len(r.Okta.Added) > 0 && r.Okta.RemovedAt == nil
}

func (s *Service) verifyOktaUser(ctx context.Context, userID string) {
	s.oktaMu.Lock() // no grant or removal for this user while we compare
	defer s.oktaMu.Unlock()
	ctx, cancel := oktaStepContext(ctx)
	defer cancel()
	groups, err := s.Okta.UserGroups(ctx, userID)
	if err != nil {
		s.Log.Warn("comparing Okta group memberships with jitd's record", "user", userID, "err", err)
	}
	in := map[string]bool{}
	for _, g := range groups {
		in[g.ID] = true
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var lost, back []*AccessRequest
	serr := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		lost, back = nil, nil
		for _, r := range d.Requests {
			if !r.oktaRunning(now) || r.Okta.UserID != userID {
				continue
			}
			at := now
			r.Okta.CheckedAt = &at // also after a failed call: try again in oktaVerifyEvery, not every tick
			if err != nil {
				continue
			}
			var missing []string
			for _, g := range r.Okta.Added {
				if !in[g] {
					missing = append(missing, g)
				}
			}
			if slices.Equal(missing, r.Okta.Missing) {
				continue
			}
			r.Okta.Missing = missing
			if len(missing) > 0 {
				lost = append(lost, clone(r))
			} else {
				back = append(back, clone(r))
			}
		}
		return len(lost)+len(back) > 0, nil
	})
	if serr != nil {
		s.Log.Error("saving the Okta comparison", "user", userID, "err", serr)
		return
	}
	for _, r := range lost {
		s.Log.Warn("the Okta user was taken out of a group while the access is still running; jitd does not add them back", "id", r.ID, "user", r.Okta.Login,
			"groups", strings.Join(r.oktaLabels(r.Okta.Missing), ", "))
	}
	for _, r := range back {
		s.Log.Info("the Okta user is back in every group of the request", "id", r.ID, "user", r.Okta.Login)
	}
}

// oktaHealth is the outcome of the last check of the Okta credentials.
type oktaHealth struct {
	mu    sync.Mutex
	at    time.Time
	err   string
	cause error // the error err is the text of
	off   bool  // Okta was off with memberships still to look after, and that was logged
}

// OktaState is how jitd's use of Okta stands, for the Okta page.
type OktaState struct {
	Enabled   bool      // credentials are set and usable (Okta may still refuse them: Err)
	Off       string    // why not, when they are not
	CheckedAt time.Time // when jitd last tried the credentials against Okta; zero if not yet
	Err       error     // what that try came back with; nil when it worked
	Held      int       // requests whose Okta memberships jitd still has to look after
}

// OktaState reports how jitd's use of Okta stands.
func (s *Service) OktaState() OktaState {
	if s.Okta == nil {
		return OktaState{Off: "this build of jitd has no Okta client"}
	}
	st := OktaState{Enabled: s.oktaEnabled(), Held: s.oktaOwed()}
	if !st.Enabled {
		st.Off = s.oktaWhyOff()
		return st
	}
	h := &s.okHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	st.CheckedAt = h.at
	if h.err != "" {
		st.Err = h.cause
	}
	return st
}

// OktaCheckNow tries the Okta credentials now rather than at the next
// check that is due, and returns what Okta said. An admin asks for this on
// the Okta page, and saving credentials there does it.
func (s *Service) OktaCheckNow(ctx context.Context) error {
	if s.Okta == nil {
		return nil
	}
	h := &s.okHealth
	h.mu.Lock()
	h.at = time.Time{}
	h.mu.Unlock()
	s.checkOkta(ctx)
	return s.OktaState().Err
}

// checkOkta checks, now and then, that the Okta credentials still work, so
// a revoked or expired token shows before the next removal needs it. (Okta
// also expires API tokens that go unused for 30 days; this keeps jitd's
// in use.)
func (s *Service) checkOkta(ctx context.Context) {
	now := s.now()
	h := &s.okHealth
	if !s.oktaEnabled() {
		// There are no credentials to check. If memberships are waiting
		// on them, say so (OktaProblems tells the admins).
		owed := s.oktaOwed()
		h.mu.Lock()
		was := h.off
		h.off, h.at, h.err, h.cause = owed > 0, time.Time{}, "", nil
		h.mu.Unlock()
		if owed > 0 && !was {
			s.Log.Error("Okta is off while jitd still has Okta group memberships to look after; they stay in place until Okta is configured again",
				"requests", owed, "err", s.oktaWhyOff())
		}
		return
	}
	h.mu.Lock()
	at, was := h.at, h.err
	h.off = false
	h.mu.Unlock()
	every := oktaCheckEvery
	if was != "" {
		every = oktaRecheckEvery
	}
	if !at.IsZero() && now.Sub(at) < every {
		return
	}
	// The check gets its own time: the tick's may have run out waiting for
	// an approval to finish, and that is not Okta failing.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oktaCheckTimeout)
	defer cancel()
	msg := ""
	err := s.Okta.Check(cctx)
	if err != nil {
		msg = err.Error()
	}
	h.mu.Lock()
	h.at, h.err, h.cause = now, msg, err
	h.mu.Unlock()
	switch {
	case msg != "" && msg != was:
		s.Log.Error("jitd cannot use the Okta API; memberships cannot be added or removed until this is fixed", "err", msg)
	case msg == "" && was != "":
		s.Log.Info("the Okta API works again")
	}
}

// OktaProblem is something about Okta an admin should look at.
type OktaProblem struct {
	RequestID string // the request it is about; empty for the connection itself
	Text      string
}

// OktaProblems lists what an admin should know about Okta right now: Okta
// is off while memberships jitd added are still in place, the env file
// cannot be read, the credentials do not work, a removal is stuck, or an
// unfinished approval could not be taken back. Empty when all is well.
func (s *Service) OktaProblems() []OktaProblem {
	if s.Okta == nil {
		return nil
	}
	var out []OktaProblem
	if !s.oktaEnabled() {
		n := s.oktaOwed()
		if n == 0 {
			return nil // Okta is not in use
		}
		out = append(out, OktaProblem{Text: fmt.Sprintf("Okta is off, but %d request(s) still have Okta group memberships that jitd added. jitd cannot remove them until Okta is configured again: %s", n, s.oktaWhyOff())})
	} else {
		if st, ok := s.Okta.(interface{ StaleSettings() string }); ok {
			if why := st.StaleSettings(); why != "" {
				out = append(out, OktaProblem{Text: "jitd cannot read its Okta settings and carries on with the ones it read last, allowlists included: " + why})
			}
		}
		h := &s.okHealth
		h.mu.Lock()
		if h.err != "" {
			out = append(out, OktaProblem{Text: "jitd cannot use the Okta API, so it cannot add or remove group memberships: " + h.err})
		}
		h.mu.Unlock()
	}
	var rs []*AccessRequest
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.OktaStuck() || (r.OktaAdding != nil && r.OktaAdding.Error != "") {
				rs = append(rs, clone(r))
			}
		}
	})
	slices.SortFunc(rs, func(a, b *AccessRequest) int { return strings.Compare(a.ID, b.ID) })
	for _, r := range rs {
		if r.OktaStuck() {
			out = append(out, OktaProblem{RequestID: r.ID, Text: fmt.Sprintf("%s is still in %s although the access through %q has ended. Removing keeps failing: %s",
				r.Okta.Login, strings.Join(r.OktaAddedLabels(), ", "), r.WorkflowName, r.Okta.Error)})
		}
		if a := r.OktaAdding; a != nil && a.Error != "" {
			out = append(out, OktaProblem{RequestID: r.ID, Text: fmt.Sprintf("an approval through %q did not finish and may have left %s in %s. Taking that back keeps failing: %s",
				r.WorkflowName, a.Login, strings.Join(r.oktaLabels(a.Groups), ", "), a.Error)})
		}
	}
	return out
}

// AdminLogins lists the admins by login, as ApproverLogins does for a flow's
// approvers.
func (s *Service) AdminLogins(ctx context.Context) ([]string, error) {
	return s.ApproverLogins(ctx, &Workflow{Approvers: s.Admins})
}
