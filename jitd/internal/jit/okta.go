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

// oktaEnabled reports whether jitd has an Okta client with credentials.
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
// expiry) and whose removal from Okta has not happened yet: jitd put the
// user in those groups, so they are jitd's to take off, not memberships
// the user had before.
func (s *Service) oktaHolders(userID string, self string) (live, leaving map[string]bool) {
	now := s.now()
	live, leaving = map[string]bool{}, map[string]bool{}
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.ID == self || r.Okta == nil || r.Okta.UserID != userID || r.Okta.RemovedAt != nil {
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

// grantOkta adds r's requester to r's Okta groups and records what it did
// in r.Okta. On failure it takes back what it added and leaves r.Okta nil.
func (s *Service) grantOkta(ctx context.Context, r *AccessRequest) error {
	if len(r.OktaGroups) == 0 {
		return nil
	}
	if !s.oktaEnabled() {
		return errors.New("okta is not configured")
	}
	if r.Requester.Tagged() || r.Requester.Login == "" {
		return errors.New("a tagged device has no Okta user")
	}
	u, err := s.Okta.FindUser(ctx, r.Requester.Login)
	if err != nil {
		return fmt.Errorf("finding the Okta user for %s: %w", r.Requester.Login, err)
	}
	if u.Status != "" && u.Status != "ACTIVE" && u.Status != "PASSWORD_EXPIRED" && u.Status != "RECOVERY" {
		return fmt.Errorf("the Okta user %s is %s, not active", u.Profile.Login, strings.ToLower(u.Status))
	}
	for _, grp := range r.OktaGroups {
		if !s.grantAllowed(grp) {
			return fmt.Errorf("Okta group %s is no longer on jitd's grant allowlist (%s)", grp.Label(), EnvOktaGrantAllowlist)
		}
	}
	g := &OktaGrant{UserID: u.ID, Login: u.Profile.Login}
	held, leaving := s.oktaHolders(u.ID, r.ID)
	var added []string // added by this call, to undo on failure
	undo := func() {
		for _, id := range added {
			if rerr := s.Okta.RemoveMember(ctx, id, u.ID); rerr != nil {
				s.Log.Error("okta grant failed and a membership could not be taken back", "id", r.ID, "group", id, "err", rerr)
			}
		}
	}
	for _, grp := range r.OktaGroups {
		if held[grp.ID] {
			// Another live jitd request already put the user there: share it.
			g.Added = append(g.Added, grp.ID)
			continue
		}
		member, err := s.Okta.IsMember(ctx, grp.ID, u.ID)
		if err != nil {
			undo()
			return fmt.Errorf("checking Okta group %s: %w", grp.Label(), err)
		}
		if member && leaving[grp.ID] {
			// jitd added this for a request that has ended and has not
			// taken it off yet. Take it over: recorded as preexisting, the
			// ended request's removal would cut this grant short.
			g.Added = append(g.Added, grp.ID)
			continue
		}
		if member {
			g.Preexisting = append(g.Preexisting, grp.ID)
			continue
		}
		if err := s.Okta.AddMember(ctx, grp.ID, u.ID); err != nil {
			undo()
			return fmt.Errorf("adding %s to Okta group %s: %w", u.Profile.Login, grp.Label(), err)
		}
		added = append(added, grp.ID)
		g.Added = append(g.Added, grp.ID)
	}
	r.Okta = g
	return nil
}

// releaseOkta removes the memberships r holds that no other live request
// still holds. r's status must already say it ended. It records the outcome
// in r.Okta and returns the error, if any; the expiry tick retries.
func (s *Service) releaseOkta(ctx context.Context, r *AccessRequest) error {
	if r.Okta == nil || len(r.Okta.Added) == 0 || r.Okta.RemovedAt != nil {
		return nil
	}
	held, _ := s.oktaHolders(r.Okta.UserID, r.ID)
	var errs []error
	for _, id := range r.Okta.Added {
		if held[id] {
			continue
		}
		if err := s.Okta.RemoveMember(ctx, id, r.Okta.UserID); err != nil {
			errs = append(errs, fmt.Errorf("removing from Okta group %s: %w", s.oktaLabel(r, id), err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		r.Okta.Error = err.Error()
		return err
	}
	now := s.now()
	r.Okta.RemovedAt, r.Okta.Error = &now, ""
	return nil
}

func (s *Service) oktaLabel(r *AccessRequest, id string) string {
	for _, g := range r.OktaGroups {
		if g.ID == id {
			return g.Label()
		}
	}
	return id
}

// oktaBatch caps how many ended requests one expiry tick removes from Okta.
const oktaBatch = 20

// releaseOktaDue removes the Okta memberships of ended requests that still
// have them. Callers hold s.mu. The API calls run outside the store lock.
func (s *Service) releaseOktaDue(ctx context.Context) {
	if !s.oktaEnabled() {
		return
	}
	var due []*AccessRequest
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.oktaPendingRemoval() {
				due = append(due, clone(r))
			}
		}
	})
	slices.SortFunc(due, func(a, b *AccessRequest) int { return a.UpdatedAt.Compare(b.UpdatedAt) })
	if len(due) > oktaBatch {
		due = due[:oktaBatch]
	}
	var done []*AccessRequest
	for _, r := range due {
		if ctx.Err() != nil {
			break
		}
		was := r.Okta.Error
		if err := s.releaseOkta(ctx, r); err != nil {
			if was != r.Okta.Error {
				s.Log.Error("removing Okta group memberships", "id", r.ID, "err", err)
			}
		} else {
			s.Log.Info("okta group memberships removed", "id", r.ID, "user", r.Okta.Login)
		}
		done = append(done, r)
	}
	if len(done) == 0 {
		return
	}
	for _, r := range done {
		if r.Attribute == "" && r.Okta.RemovedAt != nil && r.Enforcement.RemovedAt == nil {
			r.Enforcement.RemovedAt = r.Okta.RemovedAt
		}
	}
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		changed := false
		for _, r := range done {
			if cur, ok := d.Requests[r.ID]; ok && cur.Okta != nil {
				changed = changed || cur.Okta.RemovedAt == nil && r.Okta.RemovedAt != nil || cur.Okta.Error != r.Okta.Error
				cur.Okta = r.Okta
				if r.Attribute == "" {
					cur.Enforcement.RemovedAt = r.Enforcement.RemovedAt
				}
			}
		}
		return changed, nil
	})
	if err != nil {
		s.Log.Error("saving Okta removal", "err", err)
		return
	}
	for _, r := range done {
		if r.Attribute == "" && r.Okta.RemovedAt != nil {
			s.emit(r, Event{Type: EventRemoved, Actor: "system", At: *r.Okta.RemovedAt})
		}
	}
}

// oktaTimeout bounds the Okta calls of one expiry tick.
const oktaTimeout = 30 * time.Second
