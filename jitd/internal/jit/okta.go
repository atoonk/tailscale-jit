package jit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// Okta group grants.
//
// An approval through a flow with OktaGroups adds the requester's Okta user
// to each group; the end of the access (expiry or revoke) removes them
// again. Unlike a posture attribute, Okta membership cannot carry an
// expiry, so jitd does the removal itself, on its expiry tick, and keeps
// retrying until it succeeds.
//
// Memberships are shared between requests: one person may hold the same
// group through two live requests (two devices, or two flows naming the
// same group). A membership comes off only when no live request still
// holds it. A membership the user had before jitd added it (put there by
// hand, or by a rule) is recorded as Preexisting and never removed.

// oktaEnabled reports whether jitd may use Okta for something new: a grant,
// a flow that names Okta groups, an okta: principal. It is false without
// usable credentials (and it is where a switch to turn Okta off belongs).
//
// It must not gate looking after what jitd already did. Taking memberships
// back, retrying, and telling the admins run whenever there is an Okta
// client at all (see oktaUpkeep): if Okta is off while memberships are in
// place, those calls fail, and that failure is recorded and reported like
// any other.
func (s *Service) oktaEnabled() bool {
	if s.Okta == nil {
		return false
	}
	if e, ok := s.Okta.(interface{ Enabled() bool }); ok {
		return e.Enabled()
	}
	return true
}

// OktaEnabled reports whether Okta group grants are available.
func (s *Service) OktaEnabled() bool { return s.oktaEnabled() }

// resolveOktaGroups fills in the ID (and the current name) of every group
// in w, and refuses groups whose members Okta does not let jitd change.
func (s *Service) resolveOktaGroups(ctx context.Context, w *Workflow) error {
	if len(w.OktaGroups) == 0 {
		return nil
	}
	if !s.oktaEnabled() {
		return conflict("this approval flow grants Okta groups, but Okta is not configured: set OKTA_ORG_URL and either OKTA_API_TOKEN or OKTA_CLIENT_ID and OKTA_PRIVATE_KEY in jitd's env file")
	}
	actx, cancel := apiContext(ctx)
	defer cancel()
	for i, g := range w.OktaGroups {
		ref := g.ID
		if ref == "" {
			ref = g.Name
		}
		og, err := s.Okta.FindGroup(actx, ref)
		if errors.Is(err, okta.ErrNotFound) {
			return badRequest("Okta group %q not found", ref)
		}
		if err != nil {
			return apiFailed("looking up Okta group %q: %v", ref, err)
		}
		if !og.Manageable() {
			return badRequest("Okta group %q is a %s group: its members come from a directory or app, so Okta does not let jitd change them", og.Name(), og.Type)
		}
		w.OktaGroups[i] = OktaGroup{ID: og.ID, Name: og.Name()}
		if !s.grantAllowed(w.OktaGroups[i]) {
			return forbidden("Okta group %q is not on jitd's grant allowlist (%s)", og.Name(), EnvOktaGrantAllowlist)
		}
	}
	w.OktaGroups = cleanOktaGroups(w.OktaGroups) // a name and an ID may name the same group
	return nil
}

// sameGrant reports whether r asks for what w grants now. A pending request
// whose flow changed what it grants no longer fits it.
func sameGrant(r *AccessRequest, w *Workflow) bool {
	return r.Attribute == w.Attribute && slices.Equal(oktaGroupIDs(r.OktaGroups), oktaGroupIDs(w.OktaGroups))
}

// grantSummary describes what a flow grants, for timeline notes.
func grantSummary(attr string, groups []OktaGroup) string {
	var parts []string
	if attr != "" {
		parts = append(parts, attr)
	}
	if len(groups) > 0 {
		parts = append(parts, "Okta "+strings.Join(oktaLabels(groups), ", "))
	}
	return strings.Join(parts, " and ")
}

// oktaHolders returns, for user, the IDs of groups that requests other than
// self hold through jitd. live are held by a request whose access is still
// running. leaving are held by a request that has ended (or is past its
// expiry) and whose removal from Okta has not happened yet, or were added
// for an approval that did not finish (OktaAdding): jitd put the user in
// those groups, so they are jitd's to take off, not memberships the user
// had before.
func (s *Service) oktaHolders(userID string, self string) (live, leaving map[string]bool) {
	now := s.now()
	live, leaving = map[string]bool{}, map[string]bool{}
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.ID == self {
				continue
			}
			if a := r.OktaAdding; a != nil && a.UserID == userID {
				for _, g := range a.Groups {
					leaving[g] = true
				}
			}
			if r.Okta == nil || r.Okta.UserID != userID || r.Okta.RemovedAt != nil {
				continue
			}
			into := leaving
			if r.Status == StatusApproved && r.ExpiresAt != nil && r.ExpiresAt.After(now) {
				into = live
			}
			for _, g := range r.Okta.Added {
				into[g] = true
			}
		}
	})
	return live, leaving
}

// oktaKept returns the groups that taking back an unfinished approval of
// request id must leave user in: the ones a running request holds, be it
// another request or, if its grant was saved after all, this one.
func (s *Service) oktaKept(userID, id string) map[string]bool {
	keep, _ := s.oktaHolders(userID, id)
	if r := s.Request(id); r != nil && r.Status == StatusApproved && r.Okta != nil && r.Okta.RemovedAt == nil {
		for _, g := range r.Okta.Added {
			keep[g] = true
		}
	}
	return keep
}

// oktaOutcome is the result of adding a request's Okta memberships, which
// grantOutsideLock does outside the service lock.
type oktaOutcome struct {
	userID, login string     // the Okta user, once found
	grant         *OktaGrant // what to record on the request; nil if err is set
	// fresh are the IDs of the groups to take the user out of again if the
	// approval does not go through: the ones this attempt added (or tried
	// to add: a failed call may still have been applied) and the ones an
	// earlier, unfinished attempt for this request left behind.
	fresh []string
	err   error
	// recorded says this attempt wrote the request's intent (OktaAdding),
	// so it is this attempt's to settle.
	recorded bool
	used     bool // the approval was saved with grant
}

// grantOkta adds r's requester to r's Okta groups. It first works out what
// to add, then records that on the request (OktaAdding), and only then
// changes anything in Okta, so there is never a membership jitd added and
// has no record of. The outcome says what to record on the request, and
// what takeBackOkta must undo if the approval does not go through; grantOkta
// itself takes nothing back. The caller holds oktaMu and not mu.
func (s *Service) grantOkta(ctx context.Context, r *AccessRequest) *oktaOutcome {
	out := &oktaOutcome{}
	fail := func(format string, args ...any) *oktaOutcome {
		out.err = fmt.Errorf(format, args...)
		return out
	}
	if !s.oktaEnabled() {
		return fail("okta is not configured")
	}
	// Pending, for an approval; scheduled, for a start (see startDue).
	if r.Status != StatusPending && r.Status != StatusScheduled {
		return fail("the request is no longer pending") // approve reports what it is instead
	}
	if r.Requester.Tagged() || r.Requester.Login == "" {
		return fail("a tagged device has no Okta user")
	}
	u, err := s.Okta.FindUser(ctx, r.Requester.Login)
	if err != nil {
		return fail("finding the Okta user for %s: %w", r.Requester.Login, err)
	}
	if !u.Active() {
		return fail("the Okta user %s is %s, not active", u.Profile.Login, strings.ToLower(u.Status))
	}
	for _, grp := range r.OktaGroups {
		if !s.grantAllowed(grp) {
			return fail("Okta group %s is no longer on jitd's grant allowlist (%s)", grp.Label(), EnvOktaGrantAllowlist)
		}
	}
	// mine are groups an earlier attempt for this request added and could
	// not take back. They are still on record, and they are jitd's.
	mine := map[string]bool{}
	if a := r.OktaAdding; a != nil {
		if a.UserID != u.ID {
			return fail("an earlier, unfinished approval of this request added the Okta user %s to groups; jitd is still taking that back, try again in a minute", a.Login)
		}
		for _, g := range a.Groups {
			mine[g] = true
		}
	}
	out.userID, out.login = u.ID, u.Profile.Login

	// What to do, without changing anything yet.
	g := &OktaGrant{UserID: u.ID, Login: u.Profile.Login}
	held, leaving := s.oktaHolders(u.ID, r.ID)
	added := map[string]bool{} // the groups to record as Added
	var todo []string          // the groups to add the user to
	for _, grp := range r.OktaGroups {
		member, err := s.Okta.IsMember(ctx, grp.ID, u.ID)
		if err != nil {
			out.fresh = nil // nothing was changed; what an earlier attempt left stays on record
			return fail("checking Okta group %s: %w", grp.Label(), err)
		}
		switch {
		case member && held[grp.ID]:
			// Another live jitd request already put the user there: share
			// it. (If someone took the user out in Okta since, they are
			// added again below: jitd must not record access that is not
			// there.)
			added[grp.ID] = true
		case member && mine[grp.ID]:
			added[grp.ID] = true
			out.fresh = append(out.fresh, grp.ID)
		case member && leaving[grp.ID]:
			// jitd added this for a request that has ended and has not
			// taken it off yet. Take it over: recorded as preexisting, the
			// ended request's removal would cut this grant short.
			added[grp.ID] = true
		case member:
			g.Preexisting = append(g.Preexisting, grp.ID)
		default:
			todo = append(todo, grp.ID)
		}
	}

	// Record it, then do it.
	intent := &OktaIntent{UserID: u.ID, Login: u.Profile.Login, Groups: append(slices.Clone(out.fresh), todo...), At: s.now()}
	if err := s.saveOktaIntent(r.ID, intent); err != nil {
		return fail("recording the Okta change before making it: %w", err)
	}
	out.recorded = true
	for _, id := range todo {
		if err := s.Okta.AddMember(ctx, id, u.ID); err != nil {
			// Okta saying no means the user was not added, so there is
			// nothing to take back; taking it back anyway could remove a
			// membership somebody gives the user later. Any other failure
			// may still have been applied.
			if !okta.IsRefusal(err) {
				out.fresh = append(out.fresh, id)
			}
			return fail("adding %s to Okta group %s: %w", u.Profile.Login, s.oktaLabel(r, id), err)
		}
		out.fresh = append(out.fresh, id)
		added[id] = true
	}
	for _, grp := range r.OktaGroups {
		if added[grp.ID] {
			g.Added = append(g.Added, grp.ID)
		}
	}
	out.grant = g
	return out
}

// saveOktaIntent records on request id which Okta memberships an approval,
// or the start of a scheduled request, is about to add. It refuses if the
// request is no longer pending or scheduled.
func (s *Service) saveOktaIntent(id string, in *OktaIntent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		cur, ok := d.Requests[id]
		if !ok {
			return false, notFound("access request %q not found", id)
		}
		if cur.Status != StatusPending && cur.Status != StatusScheduled {
			return false, conflict("request is %s, not pending", cur.Status)
		}
		if len(in.Groups) == 0 {
			cur.OktaAdding = nil // every group is shared or was there before: nothing to undo
		} else {
			cur.OktaAdding = clone(in)
		}
		return false, nil
	})
}

// settleOktaIntent updates request id's intent after its memberships were
// taken back: gone if none are left, else narrowed to the ones that could
// not be removed, with why.
func (s *Service) settleOktaIntent(id string, left []string, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		cur, ok := d.Requests[id]
		if !ok || cur.OktaAdding == nil {
			return false, nil
		}
		if len(left) == 0 {
			cur.OktaAdding = nil
			return true, nil
		}
		changed := cur.OktaAdding.Error != why
		cur.OktaAdding.Groups, cur.OktaAdding.Error = slices.Clone(left), why
		return changed, nil
	})
	if err != nil {
		s.Log.Error("saving the outcome of taking Okta memberships back", "id", id, "err", err)
	}
}

// takeBackOkta removes the memberships a grant attempt added, when the
// approval of request id did not go through. What it cannot remove stays
// on the request's intent, and the expiry tick tries again
// (dropOktaIntents). The caller holds oktaMu and not mu.
func (s *Service) takeBackOkta(ctx context.Context, id string, out *oktaOutcome) {
	if !out.recorded {
		return // nothing was changed in Okta, and the record is as it was
	}
	keep := s.oktaKept(out.userID, id)
	var left []string
	var errs []error
	for _, g := range out.fresh {
		if keep[g] {
			continue
		}
		if err := s.Okta.RemoveMember(ctx, g, out.userID); err != nil {
			s.Log.Error("approval did not go through and an Okta membership could not be taken back; will retry", "id", id, "group", g, "user", out.login, "err", err)
			left = append(left, g)
			errs = append(errs, fmt.Errorf("removing from Okta group %s: %w", g, err))
		}
	}
	why := ""
	if err := errors.Join(errs...); err != nil {
		why = err.Error()
	}
	s.settleOktaIntent(id, left, why)
}

// releaseOkta removes the memberships r holds that no other live request
// still holds; those it leaves in place and lists in Kept. r's status must
// already say it ended. It records the outcome in r.Okta (r is a copy) and
// returns the error, if any; the expiry tick retries. The caller holds
// oktaMu and not mu.
func (s *Service) releaseOkta(ctx context.Context, r *AccessRequest) error {
	if r.Okta == nil || len(r.Okta.Added) == 0 || r.Okta.RemovedAt != nil {
		return nil
	}
	held, _ := s.oktaHolders(r.Okta.UserID, r.ID)
	var kept []string
	var errs []error
	for _, id := range r.Okta.Added {
		if held[id] {
			kept = append(kept, id)
			continue
		}
		if err := s.Okta.RemoveMember(ctx, id, r.Okta.UserID); err != nil {
			errs = append(errs, fmt.Errorf("removing from Okta group %s: %w", s.oktaLabel(r, id), err))
		}
	}
	now := s.now()
	r.Okta.TriedAt = &now
	if err := errors.Join(errs...); err != nil {
		r.Okta.Error = err.Error()
		if r.Okta.FailingSince == nil {
			r.Okta.FailingSince = &now
		}
		return err
	}
	r.Okta.RemovedAt, r.Okta.Kept, r.Okta.Error, r.Okta.FailingSince = &now, kept, "", nil
	return nil
}

func (s *Service) oktaLabel(r *AccessRequest, id string) string {
	return r.oktaLabels([]string{id})[0]
}

// oktaBatch caps how many ended requests one expiry tick removes from Okta.
const oktaBatch = 20

// releaseOktaDue removes the Okta memberships of ended requests that still
// have them: first the ones not tried yet, then the ones tried longest ago.
// A removal that keeps failing so goes to the back of the line, and a batch
// of stuck ones cannot keep a newer one from ever being tried. The caller
// must not hold mu.
func (s *Service) releaseOktaDue(ctx context.Context) {
	if s.Okta == nil {
		return
	}
	type item struct {
		id           string
		ended, tried time.Time
	}
	var due []item
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if !r.oktaPendingRemoval() {
				continue
			}
			it := item{id: r.ID, ended: r.UpdatedAt}
			if t := r.Okta.TriedAt; t != nil {
				it.tried = *t
			}
			due = append(due, it)
		}
	})
	slices.SortFunc(due, func(a, b item) int {
		if c := a.tried.Compare(b.tried); c != 0 {
			return c
		}
		if c := a.ended.Compare(b.ended); c != 0 {
			return c
		}
		return strings.Compare(a.id, b.id)
	})
	if len(due) > oktaBatch {
		due = due[:oktaBatch]
	}
	for _, it := range due {
		if ctx.Err() != nil {
			break
		}
		s.releaseOktaOne(ctx, it.id)
	}
}

// releaseOktaOne is releaseOktaLocked for the expiry tick: it takes oktaMu
// and then gives the removal its own time. The caller must not hold mu.
func (s *Service) releaseOktaOne(ctx context.Context, id string) *AccessRequest {
	s.oktaMu.Lock()
	defer s.oktaMu.Unlock()
	sctx, cancel := oktaStepContext(ctx)
	defer cancel()
	return s.releaseOktaLocked(sctx, id)
}

// releaseOktaLocked removes the Okta memberships of ended request id and
// saves the outcome. It returns the request as saved, or nil if it had
// nothing to remove. The caller holds oktaMu and not mu: the Okta calls run
// under oktaMu only, and mu is taken just for the save.
func (s *Service) releaseOktaLocked(ctx context.Context, id string) *AccessRequest {
	if s.Okta == nil {
		return nil
	}
	r := s.Request(id)
	if r == nil || !r.oktaPendingRemoval() {
		return nil
	}
	was := r.Okta.Error
	switch err := s.releaseOkta(ctx, r); {
	case err != nil:
		if was != r.Okta.Error {
			s.Log.Error("removing Okta group memberships; will retry", "id", id, "err", err)
		}
	case len(r.Okta.Kept) > 0:
		s.Log.Info("okta group memberships released; some stay because another running request holds them", "id", id, "user", r.Okta.Login,
			"kept", strings.Join(r.oktaLabels(r.Okta.Kept), ", "))
	default:
		s.Log.Info("okta group memberships removed", "id", id, "user", r.Okta.Login)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var out *AccessRequest
	gone := false    // the removal is what ended an Okta-only request's access
	cleared := false // a removal the admins were told about is no longer stuck
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		out, gone, cleared = nil, false, false
		cur, ok := d.Requests[id]
		if !ok || cur.Okta == nil {
			return false, nil
		}
		removed := cur.Okta.RemovedAt == nil && r.Okta.RemovedAt != nil
		changed := removed || cur.Okta.Error != r.Okta.Error
		// Only what the removal found out: the rest of the grant is as stored.
		cur.Okta.RemovedAt, cur.Okta.Kept, cur.Okta.TriedAt = r.Okta.RemovedAt, r.Okta.Kept, r.Okta.TriedAt
		cur.Okta.Error, cur.Okta.FailingSince = r.Okta.Error, r.Okta.FailingSince
		cleared = removed && cur.Okta.AlertedAt != nil
		if cur.Attribute == "" && cur.Okta.RemovedAt != nil && cur.Enforcement.RemovedAt == nil {
			cur.Enforcement.RemovedAt, gone = cur.Okta.RemovedAt, true
		}
		out = clone(cur)
		return changed, nil
	})
	if err != nil {
		s.Log.Error("saving Okta removal", "id", id, "err", err)
		return nil
	}
	switch {
	case out == nil:
	case gone:
		s.emit(out, Event{Type: EventRemoved, Actor: "system", At: *out.Okta.RemovedAt})
	case cleared:
		s.emit(out, Event{Type: EventOktaCleared, Actor: "system", At: *out.Okta.RemovedAt})
	}
	return out
}
