package jit

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Group grants.
//
// An approval through a flow that names groups (Okta groups today) adds the
// requester to each group; the end of the access (expiry or revoke) removes
// them again. Unlike a posture attribute, a group membership cannot carry
// an expiry jitd can rely on, so jitd does the removal itself, on its
// expiry tick, and keeps retrying until it succeeds.
//
// Memberships are shared between requests: one person may hold the same
// group through two live requests (two devices, or two flows naming the
// same group). A membership comes off only when no live request still
// holds it. A membership the user had before jitd added it (put there by
// hand, or by a rule) is recorded as Preexisting and never removed.
//
// The code here is the same for every system that has groups. What differs
// is in a groupKind (where a flow and a request keep that system's groups)
// and a groupProvider (the client, its allowlist, its health).

// errNoGroup is what a groupClient returns for a group it cannot find.
var errNoGroup = errors.New("no such group")

// groupClient is what jitd needs from a system that has groups.
type groupClient interface {
	// Member finds the member a Tailscale login stands for: its ID in that
	// system and a name for people. The error says, in full, why there is
	// none (no such user, a suspended one).
	Member(ctx context.Context, login string) (id, label string, err error)
	// Group looks a group up by its ID or its name. It returns errNoGroup
	// if there is none, and an *Error for a group whose members jitd
	// cannot change.
	Group(ctx context.Context, ref string) (GroupRef, error)
	IsMember(ctx context.Context, groupID, memberID string) (bool, error)
	// Add and Remove are safe to repeat: adding a member and removing a
	// non-member succeed.
	Add(ctx context.Context, groupID, memberID string) error
	Remove(ctx context.Context, groupID, memberID string) error
	// Holding reports which of groupIDs the member is in.
	Holding(ctx context.Context, memberID string, groupIDs []string) (map[string]bool, error)
	// Check tries the credentials.
	Check(ctx context.Context) error
	// Refused reports whether err is the system saying no to a change, so
	// that the change was certainly not made.
	Refused(err error) bool
}

// groupKind is one kind of group a flow can grant: its name, and where a
// flow and a request keep it. The stored field names differ per kind and
// the types are the same.
type groupKind struct {
	key, label string // "okta", "Okta"
	flowGroups func(*Workflow) *[]GroupRef
	reqGroups  func(*AccessRequest) *[]GroupRef
	grant      func(*AccessRequest) **GroupGrant
	adding     func(*AccessRequest) **GroupIntent
	// stuck and cleared are the event types for a removal that keeps
	// failing and one that then went through.
	stuck, cleared string
	// idRE is the shape of a group ID, to tell an ID given as a name.
	idRE *regexp.Regexp
}

var oktaKind = &groupKind{
	key: "okta", label: "Okta",
	flowGroups: func(w *Workflow) *[]GroupRef { return &w.OktaGroups },
	reqGroups:  func(r *AccessRequest) *[]GroupRef { return &r.OktaGroups },
	grant:      func(r *AccessRequest) **GroupGrant { return &r.Okta },
	adding:     func(r *AccessRequest) **GroupIntent { return &r.OktaAdding },
	stuck:      EventOktaStuck, cleared: EventOktaCleared,
	idRE: oktaGroupIDRE,
}

var googleKind = &groupKind{
	key: "google", label: "Google",
	flowGroups: func(w *Workflow) *[]GroupRef { return &w.GoogleGroups },
	reqGroups:  func(r *AccessRequest) *[]GroupRef { return &r.GoogleGroups },
	grant:      func(r *AccessRequest) **GroupGrant { return &r.Google },
	adding:     func(r *AccessRequest) **GroupIntent { return &r.GoogleAdding },
	stuck:      EventGoogleStuck, cleared: EventGoogleCleared,
	idRE: googleGroupIDRE,
}

// groupKinds lists every kind, in the order they are shown.
var groupKinds = []*groupKind{oktaKind, googleKind}

func (k *groupKind) groups(r *AccessRequest) []GroupRef   { return *k.reqGroups(r) }
func (k *groupKind) granted(r *AccessRequest) *GroupGrant { return *k.grant(r) }
func (k *groupKind) intent(r *AccessRequest) *GroupIntent { return *k.adding(r) }

// pendingRemoval reports whether r ended with memberships of this kind
// that jitd added and that are not yet confirmed removed.
func (k *groupKind) pendingRemoval(r *AccessRequest) bool {
	ended := r.Status == StatusExpired || r.Status == StatusRevoked
	g := k.granted(r)
	return ended && g != nil && len(g.Added) > 0 && g.RemovedAt == nil
}

// running reports whether r's access is running with memberships of this
// kind that jitd added.
func (k *groupKind) running(r *AccessRequest, now time.Time) bool {
	g := k.granted(r)
	return r.Status == StatusApproved && r.ExpiresAt != nil && r.ExpiresAt.After(now) &&
		g != nil && len(g.Added) > 0 && g.RemovedAt == nil
}

// stuckOn reports whether removing r's memberships of this kind has been
// failing for long enough that jitd told the admins.
func (k *groupKind) stuckOn(r *AccessRequest) bool {
	return k.pendingRemoval(r) && k.granted(r).AlertedAt != nil
}

// labels names groups of this kind by ID, with the names r was filed with.
func (k *groupKind) labels(r *AccessRequest, ids []string) []string {
	var out []string
	for _, id := range ids {
		label := id
		for _, g := range k.groups(r) {
			if g.ID == id {
				label = g.Label()
			}
		}
		out = append(out, label)
	}
	return out
}

func (k *groupKind) labelOf(r *AccessRequest, id string) string {
	return k.labels(r, []string{id})[0]
}

// grantsGroups reports whether the flow grants groups of any kind.
func (w *Workflow) grantsGroups() bool {
	for _, k := range groupKinds {
		if len(*k.flowGroups(w)) > 0 {
			return true
		}
	}
	return false
}

// wantsGroups reports whether the request asks for groups of any kind.
func (r *AccessRequest) wantsGroups() bool {
	for _, k := range groupKinds {
		if len(k.groups(r)) > 0 {
			return true
		}
	}
	return false
}

// anyPendingRemoval reports whether r ended with memberships of any kind
// still to remove.
func (r *AccessRequest) anyPendingRemoval() bool {
	for _, k := range groupKinds {
		if k.pendingRemoval(r) {
			return true
		}
	}
	return false
}

// groupsRecorded reports whether the grant of every kind of group r asks
// for is on record, and r asks for at least one.
func (r *AccessRequest) groupsRecorded() bool {
	n := 0
	for _, k := range groupKinds {
		switch {
		case k.granted(r) != nil:
			n++
		case len(k.groups(r)) > 0:
			return false
		}
	}
	return n > 0
}

// groupsRemovedAt is when r stopped holding its last membership: nil while
// a kind with memberships to remove still has them, or when no kind
// recorded a removal.
func (r *AccessRequest) groupsRemovedAt() *time.Time {
	var at *time.Time
	for _, k := range groupKinds {
		g := k.granted(r)
		if g == nil {
			continue
		}
		if g.RemovedAt == nil {
			if len(g.Added) > 0 {
				return nil
			}
			continue
		}
		if at == nil || g.RemovedAt.After(*at) {
			at = g.RemovedAt
		}
	}
	return at
}

// groupsError is the last failure to remove r's memberships, of any kind.
func (r *AccessRequest) groupsError() string {
	for _, k := range groupKinds {
		if g := k.granted(r); g != nil && g.Error != "" {
			return g.Error
		}
	}
	return ""
}

// groupProvider is a kind of group together with what this jitd has for
// it: the client, whether it is usable, its allowlist, its health.
type groupProvider struct {
	*groupKind
	client   groupClient   // nil if jitd has no client for it
	on       func() bool   // usable for something new (see oktaEnabled)
	whyOff   func() string // why not, for people
	stale    func() string // its settings could not be re-read: why
	allow    func() GroupAllowlist
	grantEnv string // the setting that holds the grant allowlist, for messages
	setup    string // how to set it up, for messages
	health   *groupHealth
}

// providers lists the group providers, in the order a grant writes them:
// Google first, whose changes take longest and are the likeliest to be
// refused (an address outside the organisation, say), so that a grant that
// will not go through fails before anything else was touched. It is built
// on each call: the clients are fields a caller may change.
func (s *Service) providers() []*groupProvider {
	return []*groupProvider{s.googleProvider(), s.oktaProvider()}
}

func (p *groupProvider) grantAllowed(g GroupRef) bool {
	return allowed(p.allow().Grant, g.ID, g.Name)
}

// resolveGroups fills in the ID (and the current name) of every group in
// w, and refuses groups whose members jitd cannot change. was is the flow
// as it is stored, when w replaces one.
//
// A group given by ID and by name must be one group: the ID is what jitd
// looks up, so a name that belongs to another group would otherwise be
// dropped without a word, and the flow would grant a group its author did
// not mean. A pair the stored flow already has is let through: that is a
// flow read and sent back after the group was renamed.
func (s *Service) resolveGroups(ctx context.Context, w, was *Workflow) error {
	for _, p := range s.providers() {
		var stored []GroupRef
		if was != nil {
			stored = *p.flowGroups(was)
		}
		if err := s.resolveGroupsOf(ctx, p, w, stored); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) resolveGroupsOf(ctx context.Context, p *groupProvider, w *Workflow, stored []GroupRef) error {
	gs := p.flowGroups(w)
	if len(*gs) == 0 {
		return nil
	}
	if !p.on() {
		return conflict("this approval flow grants %s groups, but %s is not configured: %s", p.label, p.label, p.setup)
	}
	actx, cancel := apiContext(ctx)
	defer cancel()
	for i, g := range *gs {
		ref := g.ID
		if ref == "" {
			ref = g.Name
		}
		got, err := p.client.Group(actx, ref)
		var refused *Error
		switch {
		case errors.Is(err, errNoGroup):
			return badRequest("%s group %q not found", p.label, ref)
		case errors.As(err, &refused):
			return err
		case err != nil:
			return apiFailed("looking up %s group %q: %v", p.label, ref, err)
		}
		if g.ID != "" && g.Name != "" && !strings.EqualFold(g.Name, got.Name) && !slices.Contains(stored, g) {
			return badRequest("%s group %s is %q, not %q: give a group by its id or by its name", p.label, g.ID, got.Name, g.Name)
		}
		(*gs)[i] = got
		if !p.grantAllowed(got) {
			return forbidden("%s group %q is not on jitd's grant allowlist (%s)", p.label, got.Name, p.grantEnv)
		}
	}
	*gs = cleanGroups(p.groupKind, *gs) // a name and an ID may name the same group
	return nil
}

// sameGrant reports whether r asks for what w grants now. A pending request
// whose flow changed what it grants no longer fits it.
func sameGrant(r *AccessRequest, w *Workflow) bool {
	if r.Attribute != w.Attribute {
		return false
	}
	for _, k := range groupKinds {
		if !slices.Equal(groupIDs(k.groups(r)), groupIDs(*k.flowGroups(w))) {
			return false
		}
	}
	return true
}

// grantSummary describes what a flow or a request grants, for timeline
// notes: of is where it keeps the groups of a kind.
func grantSummary(attr string, of func(*groupKind) []GroupRef) string {
	var parts []string
	if attr != "" {
		parts = append(parts, attr)
	}
	for _, k := range groupKinds {
		if gs := of(k); len(gs) > 0 {
			parts = append(parts, k.label+" "+strings.Join(groupLabels(gs), ", "))
		}
	}
	return strings.Join(parts, " and ")
}

func (w *Workflow) grantSummary() string {
	return grantSummary(w.Attribute, func(k *groupKind) []GroupRef { return *k.flowGroups(w) })
}

func (r *AccessRequest) grantSummary() string {
	return grantSummary(r.Attribute, func(k *groupKind) []GroupRef { return k.groups(r) })
}

// holders returns, for a member, the IDs of groups that requests other
// than self hold through jitd. live are held by a request whose access is
// still running. leaving are held by a request that has ended (or is past
// its expiry) and whose removal has not happened yet, or were added for an
// approval that did not finish (the intent): jitd put the member in those
// groups, so they are jitd's to take off, not memberships the member had
// before.
func (s *Service) holders(p *groupProvider, userID string, self string) (live, leaving map[string]bool) {
	now := s.now()
	live, leaving = map[string]bool{}, map[string]bool{}
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.ID == self {
				continue
			}
			if a := p.intent(r); a != nil && a.UserID == userID {
				for _, g := range a.Groups {
					leaving[g] = true
				}
			}
			gr := p.granted(r)
			if gr == nil || gr.UserID != userID || gr.RemovedAt != nil {
				continue
			}
			into := leaving
			if r.Status == StatusApproved && r.ExpiresAt != nil && r.ExpiresAt.After(now) {
				into = live
			}
			for _, g := range gr.Added {
				into[g] = true
			}
		}
	})
	return live, leaving
}

// kept returns the groups that taking back an unfinished approval of
// request id must leave the member in: the ones a running request holds,
// be it another request or, if its grant was saved after all, this one.
func (s *Service) kept(p *groupProvider, userID, id string) map[string]bool {
	keep, _ := s.holders(p, userID, id)
	if r := s.Request(id); r != nil && r.Status == StatusApproved {
		if gr := p.granted(r); gr != nil && gr.RemovedAt == nil {
			for _, g := range gr.Added {
				keep[g] = true
			}
		}
	}
	return keep
}

// groupOutcome is the result of adding a request's memberships with one
// provider, which grantOutsideLock does outside the service lock.
type groupOutcome struct {
	p             *groupProvider
	userID, login string      // the member, once found
	grant         *GroupGrant // what to record on the request; nil if err is set
	// fresh are the IDs of the groups to take the member out of again if
	// the approval does not go through: the ones this attempt added (or
	// tried to add: a failed call may still have been applied) and the
	// ones an earlier, unfinished attempt for this request left behind.
	fresh []string
	err   error
	// recorded says this attempt wrote the request's intent, so it is this
	// attempt's to settle.
	recorded bool
	// What planGroups worked out and writeGroups carries out.
	todo  []string        // the groups to add the member to
	added map[string]bool // the groups to record as Added
}

// groupsDone is the outcome of the group changes of one grant attempt: one
// outcome per provider the request names groups of.
type groupsDone struct {
	outs []*groupOutcome
	used bool // the approval was saved with these grants
}

// err is the first failure, named after its provider.
func (d *groupsDone) err() error {
	for _, out := range d.outs {
		if out.err != nil {
			return fmt.Errorf("%s: %w", out.p.key, out.err)
		}
	}
	return nil
}

// grantGroups adds r's requester to r's groups, of every provider, all or
// nothing. It first works out what to add with each provider, without
// changing anything, so a requester one provider does not know is found
// before another has added them. Then, per provider, it records what it is
// about to add on the request (the intent) and only then changes anything,
// so there is never a membership jitd added and has no record of. The
// first failure stops it. The outcomes say what to record on the request,
// and what takeBack must undo if the approval does not go through;
// grantGroups itself takes nothing back. The caller holds groupMu and not
// mu.
func (s *Service) grantGroups(ctx context.Context, r *AccessRequest) *groupsDone {
	done := &groupsDone{}
	for _, p := range s.providers() {
		if len(p.groups(r)) == 0 {
			continue
		}
		out := s.planGroups(ctx, p, r)
		done.outs = append(done.outs, out)
		if out.err != nil {
			return done
		}
	}
	for _, out := range done.outs {
		if s.writeGroups(ctx, r, out); out.err != nil {
			break
		}
	}
	return done
}

// planGroups works out what granting r's groups of p takes, without
// changing anything.
func (s *Service) planGroups(ctx context.Context, p *groupProvider, r *AccessRequest) *groupOutcome {
	out := &groupOutcome{p: p}
	fail := func(format string, args ...any) *groupOutcome {
		out.err = fmt.Errorf(format, args...)
		return out
	}
	if !p.on() {
		return fail("%s is not configured", p.key)
	}
	// Pending, for an approval; scheduled, for a start (see startDue).
	if r.Status != StatusPending && r.Status != StatusScheduled {
		return fail("the request is no longer pending") // approve reports what it is instead
	}
	if r.Requester.Tagged() || r.Requester.Login == "" {
		return fail("a tagged device has no %s user", p.label)
	}
	userID, login, err := p.client.Member(ctx, r.Requester.Login)
	if err != nil {
		return fail("%w", err)
	}
	for _, grp := range p.groups(r) {
		if !p.grantAllowed(grp) {
			return fail("%s group %s is no longer on jitd's grant allowlist (%s)", p.label, grp.Label(), p.grantEnv)
		}
	}
	// mine are groups an earlier attempt for this request added and could
	// not take back. They are still on record, and they are jitd's.
	mine := map[string]bool{}
	if a := p.intent(r); a != nil {
		if a.UserID != userID {
			return fail("an earlier, unfinished approval of this request added the %s user %s to groups; jitd is still taking that back, try again in a minute", p.label, a.Login)
		}
		for _, g := range a.Groups {
			mine[g] = true
		}
	}
	out.userID, out.login = userID, login

	out.grant = &GroupGrant{UserID: userID, Login: login}
	held, leaving := s.holders(p, userID, r.ID)
	out.added = map[string]bool{}
	for _, grp := range p.groups(r) {
		member, err := p.client.IsMember(ctx, grp.ID, userID)
		if err != nil {
			out.fresh, out.grant = nil, nil // nothing was changed; what an earlier attempt left stays on record
			return fail("checking %s group %s: %w", p.label, grp.Label(), err)
		}
		switch {
		case member && held[grp.ID]:
			// Another live jitd request already put the member there:
			// share it. (If someone took the member out since, they are
			// added again by writeGroups: jitd must not record access that
			// is not there.)
			out.added[grp.ID] = true
		case member && mine[grp.ID]:
			out.added[grp.ID] = true
			out.fresh = append(out.fresh, grp.ID)
		case member && leaving[grp.ID]:
			// jitd added this for a request that has ended and has not
			// taken it off yet. Take it over: recorded as preexisting, the
			// ended request's removal would cut this grant short.
			out.added[grp.ID] = true
		case member:
			out.grant.Preexisting = append(out.grant.Preexisting, grp.ID)
		default:
			out.todo = append(out.todo, grp.ID)
		}
	}
	return out
}

// writeGroups carries out what planGroups worked out: record it, then do
// it.
func (s *Service) writeGroups(ctx context.Context, r *AccessRequest, out *groupOutcome) {
	p, g := out.p, out.grant
	out.grant = nil
	fail := func(format string, args ...any) {
		out.err = fmt.Errorf(format, args...)
	}
	intent := &GroupIntent{UserID: out.userID, Login: out.login, Groups: append(slices.Clone(out.fresh), out.todo...), At: s.now()}
	if err := s.saveIntent(p, r.ID, intent); err != nil {
		fail("recording the %s change before making it: %w", p.label, err)
		return
	}
	out.recorded = true
	for _, id := range out.todo {
		if err := p.client.Add(ctx, id, out.userID); err != nil {
			// The system saying no means the member was not added, so
			// there is nothing to take back; taking it back anyway could
			// remove a membership somebody gives them later. Any other
			// failure may still have been applied.
			if !p.client.Refused(err) {
				out.fresh = append(out.fresh, id)
			}
			fail("adding %s to %s group %s: %w", out.login, p.label, p.labelOf(r, id), err)
			return
		}
		out.fresh = append(out.fresh, id)
		out.added[id] = true
	}
	for _, grp := range p.groups(r) {
		if out.added[grp.ID] {
			g.Added = append(g.Added, grp.ID)
		}
	}
	out.grant = g
}

// saveIntent records on request id which memberships an approval, or the
// start of a scheduled request, is about to add. It refuses if the request
// is no longer pending or scheduled.
func (s *Service) saveIntent(p *groupProvider, id string, in *GroupIntent) error {
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
			*p.adding(cur) = nil // every group is shared or was there before: nothing to undo
		} else {
			*p.adding(cur) = clone(in)
		}
		return false, nil
	})
}

// settleIntent updates request id's intent after its memberships were
// taken back: gone if none are left, else narrowed to the ones that could
// not be removed, with why.
func (s *Service) settleIntent(p *groupProvider, id string, left []string, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		cur, ok := d.Requests[id]
		if !ok || p.intent(cur) == nil {
			return false, nil
		}
		if len(left) == 0 {
			*p.adding(cur) = nil
			return true, nil
		}
		a := p.intent(cur)
		changed := a.Error != why
		a.Groups, a.Error = slices.Clone(left), why
		return changed, nil
	})
	if err != nil {
		s.Log.Error("saving the outcome of taking "+p.label+" memberships back", "id", id, "err", err)
	}
}

// takeBack removes the memberships a grant attempt added, when the
// approval of request id did not go through. What it cannot remove stays
// on the request's intent, and the expiry tick tries again (dropIntents).
// The caller holds groupMu and not mu.
func (s *Service) takeBack(ctx context.Context, id string, out *groupOutcome) {
	if !out.recorded {
		return // nothing was changed, and the record is as it was
	}
	p := out.p
	keep := s.kept(p, out.userID, id)
	var left []string
	var errs []error
	for _, g := range out.fresh {
		if keep[g] {
			continue
		}
		if err := p.client.Remove(ctx, g, out.userID); err != nil {
			s.Log.Error("approval did not go through and a "+p.label+" membership could not be taken back; will retry", "id", id, "group", g, "user", out.login, "err", err)
			left = append(left, g)
			errs = append(errs, fmt.Errorf("removing from %s group %s: %w", p.label, g, err))
		}
	}
	why := ""
	if err := errors.Join(errs...); err != nil {
		why = err.Error()
	}
	s.settleIntent(p, id, left, why)
}

// release removes the memberships r holds that no other live request still
// holds; those it leaves in place and lists in Kept. r's status must
// already say it ended. It records the outcome in r's grant (r is a copy)
// and returns the error, if any; the expiry tick retries. The caller holds
// groupMu and not mu.
func (s *Service) release(ctx context.Context, p *groupProvider, r *AccessRequest) error {
	g := p.granted(r)
	if g == nil || len(g.Added) == 0 || g.RemovedAt != nil {
		return nil
	}
	held, _ := s.holders(p, g.UserID, r.ID)
	var kept []string
	var errs []error
	for _, id := range g.Added {
		if held[id] {
			kept = append(kept, id)
			continue
		}
		if err := p.client.Remove(ctx, id, g.UserID); err != nil {
			errs = append(errs, fmt.Errorf("removing from %s group %s: %w", p.label, p.labelOf(r, id), err))
		}
	}
	now := s.now()
	g.TriedAt = &now
	if err := errors.Join(errs...); err != nil {
		g.Error = err.Error()
		if g.FailingSince == nil {
			g.FailingSince = &now
		}
		return err
	}
	g.RemovedAt, g.Kept, g.Error, g.FailingSince = &now, kept, "", nil
	return nil
}

// groupBatch caps how many ended requests one expiry tick removes from a
// provider.
const groupBatch = 20

// releaseDue removes the memberships of ended requests that still have
// them: first the ones not tried yet, then the ones tried longest ago. A
// removal that keeps failing so goes to the back of the line, and a batch
// of stuck ones cannot keep a newer one from ever being tried. The caller
// must not hold mu.
func (s *Service) releaseDue(ctx context.Context, p *groupProvider) {
	if p.client == nil {
		return
	}
	type item struct {
		id           string
		ended, tried time.Time
	}
	var due []item
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if !p.pendingRemoval(r) {
				continue
			}
			it := item{id: r.ID, ended: r.UpdatedAt}
			if t := p.granted(r).TriedAt; t != nil {
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
	if len(due) > groupBatch {
		due = due[:groupBatch]
	}
	for _, it := range due {
		if ctx.Err() != nil {
			break
		}
		s.releaseOne(ctx, p, it.id)
	}
}

// releaseOne is releaseLocked for the expiry tick: it takes groupMu and
// then gives the removal its own time. The caller must not hold mu.
func (s *Service) releaseOne(ctx context.Context, p *groupProvider, id string) *AccessRequest {
	s.groupMu.Lock()
	defer s.groupMu.Unlock()
	sctx, cancel := groupStepContext(ctx)
	defer cancel()
	return s.releaseLocked(sctx, p, id)
}

// releaseLocked removes the memberships of ended request id with p and
// saves the outcome. It returns the request as saved, or nil if it had
// nothing to remove. The caller holds groupMu and not mu: the provider's
// calls run under groupMu only, and mu is taken just for the save.
func (s *Service) releaseLocked(ctx context.Context, p *groupProvider, id string) *AccessRequest {
	if p.client == nil {
		return nil
	}
	r := s.Request(id)
	if r == nil || !p.pendingRemoval(r) {
		return nil
	}
	g := p.granted(r)
	was := g.Error
	switch err := s.release(ctx, p, r); {
	case err != nil:
		if was != g.Error {
			s.Log.Error("removing "+p.label+" group memberships; will retry", "id", id, "err", err)
		}
	case len(g.Kept) > 0:
		s.Log.Info(p.key+" group memberships released; some stay because another running request holds them", "id", id, "user", g.Login,
			"kept", strings.Join(p.labels(r, g.Kept), ", "))
	default:
		s.Log.Info(p.key+" group memberships removed", "id", id, "user", g.Login)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var out *AccessRequest
	gone := false    // the removal is what ended the access of a request with no posture attribute
	cleared := false // a removal the admins were told about is no longer stuck
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		out, gone, cleared = nil, false, false
		cur, ok := d.Requests[id]
		if !ok || p.granted(cur) == nil {
			return false, nil
		}
		cg := p.granted(cur)
		removed := cg.RemovedAt == nil && g.RemovedAt != nil
		changed := removed || cg.Error != g.Error
		// Only what the removal found out: the rest of the grant is as stored.
		cg.RemovedAt, cg.Kept, cg.TriedAt = g.RemovedAt, g.Kept, g.TriedAt
		cg.Error, cg.FailingSince = g.Error, g.FailingSince
		cleared = removed && cg.AlertedAt != nil
		if cur.Attribute == "" && cur.Enforcement.RemovedAt == nil {
			if at := cur.groupsRemovedAt(); at != nil {
				cur.Enforcement.RemovedAt, gone = at, true
			}
		}
		out = clone(cur)
		return changed, nil
	})
	if err != nil {
		s.Log.Error("saving "+p.label+" removal", "id", id, "err", err)
		return nil
	}
	switch {
	case out == nil:
	case gone:
		s.emit(out, Event{Type: EventRemoved, Actor: "system", At: *out.Enforcement.RemovedAt})
	case cleared:
		s.emit(out, Event{Type: p.cleared, Actor: "system", At: *p.granted(out).RemovedAt})
	}
	return out
}
