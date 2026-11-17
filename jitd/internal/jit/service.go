package jit

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// Service holds jitd's state transitions. All mutations are serialised by mu,
// which rules out races such as a double approve; Tailscale API calls happen
// while it is held (fine at proof-of-concept scale). The store's own lock is
// never held across a network call, so store reads (lists, pages, polling)
// stay fast: a mutation loads a copy, checks it and calls the API, then saves
// the copy. VerifyNow also takes mu, so opening a not-yet-confirmed request
// can wait behind a slow approval or expiry tick.
//
// A group provider (Okta) is slower and less dependable than the Tailscale
// API, so the calls that add and remove group memberships run without mu,
// under groupMu (see groups.go). Only the cached okta: principal lookups
// still run under mu.
type Service struct {
	Store *Store
	TS    tsapi.Client
	// Okta, if set, lets flows grant time-limited Okta group membership.
	Okta okta.Client
	// OktaLimits, if set, returns the Okta group allowlists (see
	// OktaAllowlist). Nil allows every group.
	OktaLimits func() OktaAllowlist
	// Google, if set, lets flows grant time-limited Google group
	// membership.
	Google google.Client
	// GoogleLimits, if set, returns which groups a flow may grant and
	// whose logins may be added (see GoogleLimits). Nil lets nobody be
	// added.
	GoogleLimits func() GoogleLimits
	PolicyCache  *PolicyCache
	Now          func() time.Time
	Log          *slog.Logger
	// Admins may manage approval flows, see every request and revoke any
	// access. Empty means nobody is an admin.
	Admins []Principal
	// UIPorts are the ports people reach jitd on, for the policy snippet's
	// grant to the jitd tag. Default tcp:80.
	UIPorts []string
	// Notify, if set, is told about every change to an access request once
	// it is saved (see Notifier).
	Notify Notifier

	mu sync.Mutex
	// groupMu serialises changes to group memberships, of every provider,
	// together with the store write that records them. It is taken before
	// mu, never while mu is held, so waiting for a provider does not hold
	// up anything else.
	groupMu sync.Mutex
	ocache  oktaCache
	// autoBusy holds the requests whose automatic approval is running
	// right now (guarded by mu). A pending request on an automatic flow
	// that is not in it was left behind by a jitd that stopped mid-grant.
	autoBusy map[string]bool
	// OktaAlertAfter is how long the removal of a request's group
	// memberships may keep failing before jitd tells the admins. Default
	// DefaultGroupAlertAfter.
	OktaAlertAfter time.Duration
	okHealth       groupHealth
	ggHealth       groupHealth
	// ggSeen: the last Google check found a group jitd uses, which is what
	// shows the Groups Admin role (see googleGroups.Check).
	ggSeen atomic.Bool
}

// Notifier is told about access request changes: a new request, a vote, a
// decision, an expiry, and the device read-backs (EventConfirmed,
// EventRemoved). It is called in order, with a copy of the request as it is
// after the change, while the service lock is held: it must return at once
// (queue the event) and must not call back into the Service.
type Notifier interface {
	RequestChanged(r *AccessRequest, ev Event)
}

// emit tells the Notifier about a saved change to r.
func (s *Service) emit(r *AccessRequest, ev Event) {
	if s.Notify != nil && r != nil {
		s.Notify.RequestChanged(clone(r), ev)
	}
}

// emitVerified reports a read-back that confirmed the attribute present or
// gone, given the enforcement before and after.
func (s *Service) emitVerified(r *AccessRequest, was Enforcement) {
	switch {
	case was.ConfirmedAt == nil && r.Enforcement.ConfirmedAt != nil:
		s.emit(r, Event{Type: EventConfirmed, Actor: "system", At: *r.Enforcement.ConfirmedAt})
	case was.RemovedAt == nil && r.Enforcement.RemovedAt != nil:
		s.emit(r, Event{Type: EventRemoved, Actor: "system", At: *r.Enforcement.RemovedAt})
	}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// ---- Workflows ----

// ListWorkflows returns all workflows sorted by name.
func (s *Service) ListWorkflows() []*Workflow {
	var out []*Workflow
	s.Store.View(func(d *Data) {
		for _, w := range d.Workflows {
			out = append(out, clone(w))
		}
	})
	slices.SortFunc(out, func(a, b *Workflow) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return out
}

// GetWorkflow returns one workflow.
func (s *Service) GetWorkflow(id string) (*Workflow, error) {
	var out *Workflow
	s.Store.View(func(d *Data) {
		if w, ok := d.Workflows[id]; ok {
			out = clone(w)
		}
	})
	if out == nil {
		return nil, notFound("workflow %q not found", id)
	}
	return out, nil
}

// CreateWorkflow validates and stores a new workflow.
func (s *Service) CreateWorkflow(w Workflow) (*Workflow, error) {
	w.Normalize()
	// The Okta lookups only touch w: they run before the lock is taken.
	if err := s.resolveGroups(context.Background(), &w, nil); err != nil {
		return nil, err
	}
	if err := s.checkOktaPrincipals(context.Background(), &w); err != nil {
		return nil, err
	}
	roleIDs := s.oktaRoleGroups(context.Background(), "", &w)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := w.Validate(); err != nil {
		return nil, err
	}
	now := s.now()
	w.ID, w.CreatedAt, w.UpdatedAt = NewID("wf_"), now, now
	markAutoApprove(nil, &w, now)
	err := s.Store.Update(func(d *Data) error {
		if err := attributeFree(d, w.Attribute, ""); err != nil {
			return err
		}
		if err := s.selfServeRole(d, &w, roleIDs); err != nil {
			return err
		}
		d.Workflows[w.ID] = clone(&w)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.Log.Info("approval flow created", "id", w.ID, "name", w.Name, "by", w.UpdatedBy, "auto_approve", w.AutoApprove)
	return &w, nil
}

// markAutoApprove records on w who made it automatic and when. On a flow
// that stays automatic, an edit to who may request it, what it grants or
// for how long approves what follows as much as the first one did, so it
// takes the record over; any other edit keeps it.
func markAutoApprove(old, w *Workflow, now time.Time) {
	switch {
	case !w.AutoApprove:
		w.AutoApproveBy, w.AutoApproveAt = "", nil
	case old != nil && old.AutoApprove && sameAutoScope(old, w):
		w.AutoApproveBy, w.AutoApproveAt = old.AutoApproveBy, old.AutoApproveAt
	default:
		w.AutoApproveBy, w.AutoApproveAt = w.UpdatedBy, &now
	}
}

// sameAutoScope reports whether a and b let the same people request the
// same access for as long.
func sameAutoScope(a, b *Workflow) bool {
	if a.Attribute != b.Attribute || a.MaxDuration != b.MaxDuration || !slices.Equal(a.Requesters, b.Requesters) {
		return false
	}
	for _, k := range groupKinds {
		if !slices.EqualFunc(*k.flowGroups(a), *k.flowGroups(b), func(x, y GroupRef) bool { return x.ID == y.ID }) {
			return false
		}
	}
	return true
}

// selfServe reports whether f hands out what it grants with nobody but the
// requester deciding: it approves automatically, or one approval is enough
// and people may approve their own request.
func selfServe(f *Workflow) bool {
	return f.AutoApprove || (f.AllowSelfApproval && f.ApprovalsRequired <= 1)
}

// oktaRoleGroups resolves the okta: principals that carry a role (the
// admins, and the approvers of w and of every other stored flow) to Okta
// group IDs, for selfServeRole: the text of a principal can differ from the
// name a flow stored (a group renamed in Okta), the ID cannot. A principal
// that cannot be looked up is left out and compared by its text. It calls
// Okta, so it runs before the service lock is taken; id is w's ID, empty
// for a new flow.
func (s *Service) oktaRoleGroups(ctx context.Context, id string, w *Workflow) map[string]string {
	if !s.oktaEnabled() {
		return nil
	}
	var refs []string
	add := func(ps []Principal) {
		for _, p := range ps {
			if p.IsOkta() {
				refs = append(refs, p.OktaRef())
			}
		}
	}
	handsOut := selfServe(w) && len(w.OktaGroups) > 0
	add(s.Admins)
	add(w.Approvers)
	s.Store.View(func(d *Data) {
		for _, o := range d.Workflows {
			if o.ID != id {
				add(o.Approvers)
				handsOut = handsOut || (selfServe(o) && len(o.OktaGroups) > 0)
			}
		}
	})
	if !handsOut || len(refs) == 0 {
		return nil
	}
	ids := map[string]string{}
	for _, ref := range refs {
		if g, err := s.oktaGroup(ctx, ref); err == nil {
			ids[ref] = g.ID
		}
	}
	return ids
}

// selfServeRole refuses to save w when a flow that needs nobody but the
// requester (selfServe) would then hand out an Okta group whose members,
// through an okta: principal, approve requests in a flow or are jitd
// admins: whoever may request it could give themselves that role. d holds
// the other flows; ids is what oktaRoleGroups resolved.
func (s *Service) selfServeRole(d *Data, w *Workflow, ids map[string]string) error {
	flows := []*Workflow{w}
	for _, o := range d.Workflows {
		if o.ID != w.ID {
			flows = append(flows, o)
		}
	}
	type role struct {
		ref, what string
		of        *Workflow // nil for the admins
	}
	var roles []role
	for _, p := range s.Admins {
		if p.IsOkta() {
			roles = append(roles, role{ref: p.OktaRef(), what: "are jitd admins"})
		}
	}
	for _, f := range flows {
		for _, p := range f.Approvers {
			if p.IsOkta() {
				roles = append(roles, role{p.OktaRef(), fmt.Sprintf("are approvers in approval flow %q", f.Name), f})
			}
		}
	}
	means := func(ref string, g OktaGroup) bool {
		if id, ok := ids[ref]; ok && g.ID != "" {
			return id == g.ID
		}
		return g.named(ref)
	}
	for _, f := range flows {
		if !selfServe(f) {
			continue
		}
		for _, g := range f.OktaGroups {
			for _, ro := range roles {
				if !means(ro.ref, g) || (f != w && ro.of != w) {
					continue
				}
				if f.AutoApprove {
					return conflict("approval flow %q would hand out the Okta group %q automatically, and members of that group %s: anyone who may request it could give themselves that role with nobody deciding. Use another group, or let approvers decide requests for this one",
						f.Name, g.Label(), ro.what)
				}
				return conflict("approval flow %q lets people approve their own request for the Okta group %q, and members of that group %s: one person could give themselves that role with nobody else deciding. Use another group, require a second approval, or do not allow approving your own request",
					f.Name, g.Label(), ro.what)
			}
		}
	}
	return nil
}

// UpdateWorkflow replaces a workflow's editable fields.
func (s *Service) UpdateWorkflow(id string, w Workflow) (*Workflow, error) {
	w.Normalize()
	// The Okta lookups only touch w: they run before the lock is taken.
	was, _ := s.GetWorkflow(id) // nil when there is none; the update below says so
	if err := s.resolveGroups(context.Background(), &w, was); err != nil {
		return nil, err
	}
	if err := s.checkOktaPrincipals(context.Background(), &w); err != nil {
		return nil, err
	}
	roleIDs := s.oktaRoleGroups(context.Background(), id, &w)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := w.Validate(); err != nil {
		return nil, err
	}
	var out *Workflow
	var expired []*AccessRequest
	var wasAuto bool
	err := s.Store.Update(func(d *Data) error {
		old, ok := d.Workflows[id]
		if !ok {
			return notFound("workflow %q not found", id)
		}
		if err := attributeFree(d, w.Attribute, id); err != nil {
			return err
		}
		now := s.now()
		w.ID, w.CreatedAt, w.UpdatedAt = id, old.CreatedAt, now
		wasAuto = old.AutoApprove
		markAutoApprove(old, &w, now)
		if err := s.selfServeRole(d, &w, roleIDs); err != nil {
			return err
		}
		d.Workflows[id] = clone(&w)
		out = clone(&w)
		expired = nil
		// Pending requests follow the flow as it is now: a new attribute
		// means they ask for something else (they expire, so the requester
		// can file again), and a changed quorum applies to them.
		for _, r := range d.Requests {
			if r.WorkflowID != id || r.Status != StatusPending {
				continue
			}
			if !sameGrant(r, &w) {
				r.Status, r.UpdatedAt = StatusExpired, now
				r.Timeline = append(r.Timeline, Event{Type: "expired", Actor: "system", At: now,
					Note: fmt.Sprintf("the approval flow now grants %s instead of %s; file a new request", w.grantSummary(), r.grantSummary())})
				expired = append(expired, clone(r))
				continue
			}
			if w.AutoApprove && !old.AutoApprove {
				// It was filed for people to decide, and the flow may now
				// have no approvers at all. Granting it here, on a flow
				// edit, would surprise everyone: a new request is granted
				// at once.
				r.Status, r.UpdatedAt = StatusExpired, now
				r.Timeline = append(r.Timeline, Event{Type: "expired", Actor: "system", At: now,
					Note: "the approval flow now approves requests automatically; file a new request"})
				expired = append(expired, clone(r))
				continue
			}
			r.ApprovalsRequired = w.ApprovalsRequired
		}
		return nil
	})
	if err == nil {
		s.Log.Info("approval flow changed", "id", id, "name", w.Name, "by", w.UpdatedBy, "auto_approve", w.AutoApprove, "was_auto_approve", wasAuto)
		for _, r := range expired {
			s.emit(r, r.Timeline[len(r.Timeline)-1])
		}
	}
	return out, err
}

// attributeFree rejects a second flow for the same attribute: revoking one
// would silently leave the other's access in place.
func attributeFree(d *Data, attr, selfID string) error {
	if attr == "" {
		return nil
	}
	for _, o := range d.Workflows {
		if o.ID != selfID && o.Attribute == attr {
			return conflict("approval flow %q already sets %s; one flow per posture attribute", o.Name, attr)
		}
	}
	return nil
}

// OrEmpty returns s, or an empty (not nil) slice, so JSON shows [] not null.
func OrEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// DeleteWorkflow removes a workflow that has no pending or approved requests.
func (s *Service) DeleteWorkflow(id string) error {
	s.mu.Lock() // so a Submit cannot slip in between its workflow lookup and its write
	defer s.mu.Unlock()
	return s.Store.Update(func(d *Data) error {
		if _, ok := d.Workflows[id]; !ok {
			return notFound("workflow %q not found", id)
		}
		for _, r := range d.Requests {
			if r.WorkflowID == id && (r.Status == StatusPending || r.Status == StatusApproved || r.Status == StatusScheduled) {
				return conflict("workflow has %s request %s; decline or revoke it first", r.Status, r.ID)
			}
		}
		delete(d.Workflows, id)
		return nil
	})
}

// ---- Requestable ----

// Requestable is one approval flow the caller may request through.
type Requestable struct {
	WorkflowID        string      `json:"workflow_id"`
	WorkflowName      string      `json:"workflow_name"`
	Description       string      `json:"description,omitempty"`
	Attribute         string      `json:"attribute"`             // the posture attribute an approval sets
	OktaGroups        []OktaGroup `json:"okta_groups,omitempty"` // Okta groups an approval adds the requester to
	GoogleGroups      []GroupRef  `json:"google_groups,omitempty"`
	Resources         []Resource  `json:"resources"` // "Gives access to", as told by the admin
	Policy            *PolicyUse  `json:"policy,omitempty"`
	MaxDuration       Duration    `json:"max_duration"`
	DefaultDuration   Duration    `json:"default_duration"`
	Approvers         []Principal `json:"approvers"`
	AllowSelfApproval bool        `json:"allow_self_approval"`
	ApprovalsRequired int         `json:"approvals_required"`
	AutoApprove       bool        `json:"auto_approve,omitempty"` // granted on submit, with no approver
	// The caller's newest pending or approved request through this flow for
	// their own device, if any.
	ActiveRequestID  string     `json:"active_request_id,omitempty"`
	ActiveRequestURL string     `json:"active_request_url,omitempty"` // set by the HTTP layer
	ActiveStatus     Status     `json:"active_status,omitempty"`
	ActiveExpiresAt  *time.Time `json:"active_expires_at,omitempty"`
}

// Requestable lists the approval flows id may request through, sorted by
// name.
func (s *Service) Requestable(ctx context.Context, id Identity) []Requestable {
	now := s.now()
	var out []Requestable
	for _, w := range s.ListWorkflows() {
		if w.Disabled || !s.matches(ctx, w.Requesters, id) || (!w.AutoApprove && !s.quorumReachable(ctx, w, id)) {
			continue
		}
		out = append(out, Requestable{
			WorkflowID: w.ID, WorkflowName: w.Name, Description: w.Description,
			Attribute: w.Attribute, OktaGroups: w.OktaGroups, GoogleGroups: w.GoogleGroups, Resources: OrEmpty(w.Resources), Policy: s.PolicyUse(ctx, w),
			MaxDuration: w.MaxDuration, DefaultDuration: w.DefaultDuration, Approvers: OrEmpty(w.Approvers),
			AllowSelfApproval: w.AllowSelfApproval, ApprovalsRequired: w.ApprovalsRequired, AutoApprove: w.AutoApprove,
		})
	}
	s.Store.View(func(d *Data) {
		for i := range out {
			var best *AccessRequest
			for _, r := range d.Requests {
				if r.TargetDeviceID != id.DeviceID || r.WorkflowID != out[i].WorkflowID {
					continue
				}
				if r.isLive(now) && (best == nil || r.CreatedAt.After(best.CreatedAt)) {
					best = r
				}
			}
			if best != nil {
				out[i].ActiveRequestID, out[i].ActiveStatus = best.ID, best.Status
				if best.ExpiresAt != nil {
					t := *best.ExpiresAt
					out[i].ActiveExpiresAt = &t
				}
			}
		}
	})
	return out
}

// ---- Requests ----

// Scope selects which requests a viewer is asking for.
type Scope string

const (
	ScopeMine      Scope = "mine"      // submitted by, or targeting, the viewer
	ScopeApprovals Scope = "approvals" // other people's requests through workflows the viewer approves for
	ScopeAll       Scope = "all"       // everything the viewer may see
)

// ListFilter narrows ListRequests. Viewer is required: nobody sees requests
// outside their own, those they approve for, or everything if an admin.
type ListFilter struct {
	Status Status
	Viewer Identity
	Scope  Scope // default ScopeAll
}

// ListRequests returns the requests f.Viewer may see, newest first.
func (s *Service) ListRequests(ctx context.Context, f ListFilter) []*AccessRequest {
	var out []*AccessRequest
	admin := s.IsAdmin(ctx, f.Viewer)
	approves := map[string]bool{} // workflow ID -> viewer is an approver
	for _, w := range s.ListWorkflows() {
		approves[w.ID] = s.matches(ctx, w.Approvers, f.Viewer)
	}
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if f.Status != "" && r.Status != f.Status {
				continue
			}
			mine := IsMine(f.Viewer, r)
			switch f.Scope {
			case ScopeMine:
				if !mine {
					continue
				}
			case ScopeApprovals:
				if !approves[r.WorkflowID] || mine { // other people's requests only
					continue
				}
			default:
				if !admin && !mine && !approves[r.WorkflowID] {
					continue
				}
			}
			out = append(out, clone(r))
		}
	})
	slices.SortFunc(out, func(a, b *AccessRequest) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	for _, r := range out {
		s.CountVotes(ctx, r)
	}
	return out
}

// CountVotes sets r.ApprovalsCounted. While r is pending that is the votes
// that still count under the flow as it is now (an approver removed from
// the flow no longer counts); after that, every vote cast.
func (s *Service) CountVotes(ctx context.Context, r *AccessRequest) {
	if r == nil {
		return
	}
	r.ApprovalsCounted = len(r.Approvals)
	if r.Status != StatusPending {
		return
	}
	if w, err := s.GetWorkflow(r.WorkflowID); err == nil {
		r.ApprovalsCounted = s.validVotes(ctx, r, w)
	}
}

// GetRequest returns one request, or not-found if it does not exist or
// viewer may not see it (requests are not revealed to strangers).
func (s *Service) GetRequest(ctx context.Context, viewer Identity, id string) (*AccessRequest, error) {
	var out *AccessRequest
	s.Store.View(func(d *Data) {
		if r, ok := d.Requests[id]; ok {
			out = clone(r)
		}
	})
	if out == nil || !s.CanView(ctx, viewer, out) {
		return nil, notFound("access request %q not found", id)
	}
	s.CountVotes(ctx, out)
	return out, nil
}

// IsAdmin reports whether id is covered by the configured admin principals.
func (s *Service) IsAdmin(ctx context.Context, id Identity) bool {
	return len(s.Admins) > 0 && s.matches(ctx, s.Admins, id)
}

// IsApprover reports whether id approves for at least one workflow.
func (s *Service) IsApprover(ctx context.Context, id Identity) bool {
	for _, w := range s.ListWorkflows() {
		if s.matches(ctx, w.Approvers, id) {
			return true
		}
	}
	return false
}

// CanView reports whether viewer may see r: admins, the requester, the
// target device, and the workflow's approvers.
func (s *Service) CanView(ctx context.Context, viewer Identity, r *AccessRequest) bool {
	if IsMine(viewer, r) || s.IsAdmin(ctx, viewer) {
		return true
	}
	w, err := s.GetWorkflow(r.WorkflowID)
	return err == nil && s.matches(ctx, w.Approvers, viewer)
}

// quorumReachable reports whether enough people could ever approve a request
// from requester. Logins and policy groups (resolved through the policy
// cache) are counted; tags and autogroups may hold anyone, so they are
// assumed enough, as is a group that cannot be resolved right now.
func (s *Service) quorumReachable(ctx context.Context, w *Workflow, requester Identity) bool {
	people := map[string]bool{}
	for _, p := range w.Approvers {
		switch {
		case p.IsLogin():
			people[strings.ToLower(string(p))] = true
		case p.IsOkta():
			if !s.oktaEnabled() {
				continue // matches nobody
			}
			keys, err := s.oktaGroupMemberKeys(ctx, p.OktaRef())
			if err != nil {
				return true
			}
			for _, k := range keys {
				people[k] = true
			}
		case strings.HasPrefix(string(p), "group:"):
			if s.PolicyCache == nil {
				return true
			}
			groups, err := s.PolicyCache.Groups(ctx)
			if err != nil {
				return true
			}
			for _, m := range groups[string(p)] {
				people[strings.ToLower(m)] = true
			}
		default:
			return true
		}
	}
	if !w.AllowSelfApproval && !requester.Tagged() {
		delete(people, strings.ToLower(requester.Login))
	}
	return len(people) >= max(1, w.ApprovalsRequired)
}

// cleanNote trims a decision note and checks it like a reason.
func cleanNote(note string) (string, error) {
	return cleanText("note", note)
}

// cleanText trims free text from a member (a reason or a note), caps its
// length and refuses control characters other than newlines and tabs. Admins
// read this text in terminals too (the sqlite3 command line prints it raw), so
// an escape sequence in it could rewrite what they see.
func cleanText(field, text string) (string, error) {
	text = strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
	if utf8.RuneCountInString(text) > MaxNoteLen {
		return "", badRequest("%s is too long (max %d characters)", field, MaxNoteLen)
	}
	for _, r := range text {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return "", badRequest("%s contains a control character (%U)", field, r)
		}
	}
	return text, nil
}

// IsMine reports whether r was submitted by id or targets id's device. It is
// the one definition of "my request" for the service, the pages and the
// templates.
func IsMine(id Identity, r *AccessRequest) bool {
	return isSelf(id, r.Requester) || (id.DeviceID != "" && r.TargetDeviceID == id.DeviceID)
}

// NewRequest is the body of POST /v1/requests. Access is always for the
// device the caller is on; there is deliberately no way to name another
// device, as that would let anyone put a grant on someone else's machine.
type NewRequest struct {
	WorkflowID string   `json:"workflow_id"`
	Duration   Duration `json:"duration"` // default: the workflow's default_duration, else its max_duration
	Reason     string   `json:"reason"`   // required
	// StartAt schedules the access for later: approvers decide ahead of time,
	// and access is granted at StartAt for Duration. Empty, or within a
	// minute of now, means now. At most MaxScheduleAhead away.
	StartAt *time.Time `json:"start_at,omitempty"`
}

// MaxScheduleAhead is how far ahead a request may be scheduled.
const MaxScheduleAhead = Duration(30 * 24 * time.Hour)

// MaxNoteLen bounds reasons and decision notes so a member cannot grow the
// store without limit.
const MaxNoteLen = 2000

// Submit files a pending access request for caller.
func (s *Service) Submit(ctx context.Context, caller Identity, in NewRequest) (*AccessRequest, error) {
	r, auto, err := s.submit(ctx, caller, in)
	if err != nil || !auto {
		return r, err
	}
	defer func() {
		s.mu.Lock()
		delete(s.autoBusy, r.ID)
		s.mu.Unlock()
	}()
	return s.autoApprove(ctx, r.ID)
}

// submit is Submit under the service lock. It reports whether the flow
// approves on its own, which Submit then does without the lock held.
func (s *Service) submit(ctx context.Context, caller Identity, in NewRequest) (_ *AccessRequest, auto bool, _ error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := s.GetWorkflow(in.WorkflowID)
	if err != nil {
		return nil, false, err
	}
	if !s.matches(ctx, w.Requesters, caller) {
		return nil, false, forbidden("%s is not a requester in approval flow %q", caller.Actor(), w.Name)
	}
	if w.Disabled {
		return nil, false, conflict("approval flow %q is disabled", w.Name)
	}
	if w.AutoApprove && browserOnly(caller, w) != nil {
		// With nobody deciding, the request is the decision.
		return nil, false, forbidden("approval flow %q approves requests automatically and is for the browser only: request it there", w.Name)
	}
	for _, p := range s.providers() {
		if len(*p.flowGroups(w)) == 0 {
			continue
		}
		if caller.Tagged() {
			return nil, false, forbidden("approval flow %q grants %s groups, and a tagged device has no %s user", w.Name, p.label, p.label)
		}
		if !p.on() {
			return nil, false, conflict("approval flow %q grants %s groups, but %s is not configured", w.Name, p.label, p.label)
		}
	}
	dur := in.Duration
	if dur == 0 {
		dur = cmp.Or(w.DefaultDuration, w.MaxDuration)
	}
	if dur < Duration(time.Minute) || dur > w.MaxDuration {
		return nil, false, badRequest("duration must be between 1 minute and %s", w.MaxDuration.Human())
	}
	reason, err := cleanText("reason", in.Reason)
	if err != nil {
		return nil, false, err
	}
	if reason == "" {
		return nil, false, badRequest("reason is required")
	}
	if !w.AutoApprove && !s.quorumReachable(ctx, w, caller) {
		why := "it has fewer approvers than that"
		if !w.AllowSelfApproval && s.matches(ctx, w.Approvers, caller) {
			why = "you are one of its approvers, and the flow does not allow approving your own request"
		}
		return nil, false, conflict("not enough people can approve %q: it needs %s, and %s", w.Name, plural(max(1, w.ApprovalsRequired), "approval"), why)
	}
	target := caller.DeviceID
	if target == "" {
		return nil, false, badRequest("cannot tell which device you are on")
	}
	now := s.now()
	var startAt *time.Time
	if in.StartAt != nil && in.StartAt.After(now.Add(time.Minute)) {
		if in.StartAt.After(now.Add(time.Duration(MaxScheduleAhead))) {
			return nil, false, badRequest("a request can start at most %s ahead", MaxScheduleAhead.Human())
		}
		t := in.StartAt.UTC().Truncate(time.Second)
		startAt = &t
	} else if in.StartAt != nil && in.StartAt.Before(now.Add(-time.Minute)) {
		return nil, false, badRequest("the start time is in the past")
	}
	// One live request per flow and device at a time: point at an existing
	// one whose window overlaps instead of stacking a second. Requests for
	// different times (today, and a window next week) can coexist.
	newStart := now
	if startAt != nil {
		newStart = *startAt
	}
	newEnd := newStart.Add(time.Duration(dur))
	var existing *AccessRequest
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.WorkflowID != w.ID || r.TargetDeviceID != target || !r.isLive(now) {
				continue
			}
			if start, end := r.window(now); start.Before(newEnd) && newStart.Before(end) && (existing == nil || r.CreatedAt.After(existing.CreatedAt)) {
				existing = clone(r) // View's data must not escape
			}
		}
	})
	if existing != nil {
		e := conflict("this device already has a request for %q for that time, and it is %s (%s)", w.Name, existing.Status, existing.ID)
		e.RequestID = existing.ID
		return nil, false, e
	}
	r := &AccessRequest{
		ID: NewID("req_"), WorkflowID: w.ID, WorkflowName: w.Name, Attribute: w.Attribute, Resources: OrEmpty(w.Resources),
		Requester: caller, TargetDeviceID: target, Duration: dur, StartAt: startAt, Reason: reason,
		Status: StatusPending, CreatedAt: now, UpdatedAt: now, ApprovalsRequired: max(1, w.ApprovalsRequired),
	}
	for _, k := range groupKinds {
		*k.reqGroups(r) = *k.flowGroups(w)
	}
	note := fmt.Sprintf("for %s: %s", dur.Human(), reason)
	if startAt != nil {
		note = fmt.Sprintf("for %s from %s: %s", dur.Human(), startAt.Format(timeFmt), reason)
	}
	r.Timeline = append(r.Timeline, Event{Type: "submitted", Actor: caller.Actor(), Note: note, Via: caller.Via, SlackUser: caller.SlackUser, At: now})
	if err := s.Store.Update(func(d *Data) error { d.Requests[r.ID] = clone(r); return nil }); err != nil {
		return nil, false, err
	}
	s.Log.Info("access request submitted", "id", r.ID, "by", caller.Actor(), "grants", w.grantSummary(), "duration", dur)
	s.emit(r, r.Timeline[len(r.Timeline)-1])
	if w.AutoApprove {
		if s.autoBusy == nil {
			s.autoBusy = map[string]bool{}
		}
		s.autoBusy[r.ID] = true
	}
	return r, w.AutoApprove, nil
}

// AutoActor is who an automatic approval is recorded as.
const AutoActor = "jitd (automatic approval)"

// AutoApproved reports whether the request was approved by its flow, with
// nobody deciding.
func (r *AccessRequest) AutoApproved() bool {
	return slices.ContainsFunc(r.Timeline, func(e Event) bool { return e.Type == "approved" && e.Actor == AutoActor })
}

// autoApprove grants request id, just submitted through a flow that
// approves on its own. It grants the way Approve does, with the Okta calls
// outside the service lock. If the grant fails, the request is cancelled
// rather than left pending with nobody to approve it, and the requester can
// submit again.
func (s *Service) autoApprove(ctx context.Context, id string) (*AccessRequest, error) {
	out, err := s.grantOutsideLock(ctx, id, func(og *groupsDone) (*AccessRequest, bool, error) {
		return s.autoGrant(ctx, id, og)
	})
	if err == nil {
		return out, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.Request(id)
	switch {
	case r == nil:
		return nil, err
	case r.Status == StatusApproved:
		// An approver got there first; the access is in place either way.
		return r, nil
	case r.Status == StatusPending:
		now := s.now()
		r.Status, r.UpdatedAt = StatusCancelled, now
		r.Timeline = append(r.Timeline, Event{Type: "cancelled", Actor: AutoActor, At: now,
			Note: "automatic approval failed, so the request was cancelled; submit it again once the problem is fixed"})
		if serr := s.save(r); serr != nil {
			return nil, serr
		}
		s.emit(r, r.Timeline[len(r.Timeline)-1])
	}
	e := AsError(err)
	e.RequestID = id
	return nil, e
}

// autoGrant is autoApprove under the service lock. Like approve, it is
// called twice for a grant that includes Okta groups.
func (s *Service) autoGrant(ctx context.Context, id string, og *groupsDone) (_ *AccessRequest, needGroups bool, _ error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, w, err := s.load(id)
	if err != nil {
		return nil, false, err
	}
	// The request and its flow may have changed since submit let go of the
	// lock: grant only what the flow still grants on its own.
	if r.Status != StatusPending {
		return nil, false, conflict("request is %s, not pending", r.Status)
	}
	if !w.AutoApprove {
		return nil, false, conflict("approval flow %q no longer approves requests automatically", w.Name)
	}
	if w.Disabled {
		return nil, false, conflict("approval flow %q is disabled; no new access can be granted", w.Name)
	}
	if why := s.stale(ctx, r, w); why != "" {
		return nil, false, conflict("%s", why)
	}
	r.UpdatedAt = s.now()
	note := "approved automatically by the flow"
	if w.AutoApproveBy != "" {
		note += ", as set by " + w.AutoApproveBy
	}
	return s.grant(ctx, r, w, Event{Actor: AutoActor}, note, false, og)
}

// RecordSlackMessages notes Slack messages posted about request id, so they
// can be updated later. Bookkeeping: it does not count as a change.
func (s *Service) RecordSlackMessages(id string, ms []SlackMessage) error {
	if len(ms) == 0 {
		return nil
	}
	s.mu.Lock() // an action in flight must not save over it
	defer s.mu.Unlock()
	return s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		r, ok := d.Requests[id]
		if !ok {
			return false, notFound("access request %q not found", id)
		}
		for _, m := range ms {
			if !slices.ContainsFunc(r.Slack, func(x SlackMessage) bool { return x.Channel == m.Channel && x.TS == m.TS }) {
				r.Slack = append(r.Slack, m)
			}
		}
		return false, nil
	})
}

// Request returns a copy of request id, without a visibility check (for
// internal callers such as notifiers), or nil.
func (s *Service) Request(id string) *AccessRequest {
	var out *AccessRequest
	s.Store.View(func(d *Data) {
		if r, ok := d.Requests[id]; ok {
			out = clone(r)
		}
	})
	return out
}

// Requests returns copies of every request keep returns true for, in no
// particular order. For internal callers such as notifiers; it does no
// visibility check.
func (s *Service) Requests(keep func(*AccessRequest) bool) []*AccessRequest {
	var out []*AccessRequest
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if keep == nil || keep(r) {
				out = append(out, clone(r))
			}
		}
	})
	return out
}

// ApproverLogins lists the people who approve for w by login: named logins,
// plus the members of group: principals (through the policy cache). tag: and
// autogroup: approvers are left out; they are not people one can name.
func (s *Service) ApproverLogins(ctx context.Context, w *Workflow) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(login string) {
		if k := strings.ToLower(strings.TrimSpace(login)); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	var groups map[string][]string
	var groupsErr, oktaErr error
	loaded := false
	for _, p := range w.Approvers {
		switch {
		case p.IsLogin():
			add(string(p))
		case strings.HasPrefix(string(p), "group:"):
			if !loaded && s.PolicyCache != nil {
				groups, groupsErr = s.PolicyCache.Groups(ctx)
				loaded = true
			}
			for _, m := range groups[string(p)] {
				add(m)
			}
		case p.IsOkta() && s.oktaEnabled():
			keys, err := s.oktaGroupMemberKeys(ctx, p.OktaRef())
			if err != nil {
				oktaErr = err
			}
			for _, k := range keys {
				add(k)
			}
		}
	}
	if groupsErr != nil {
		groupsErr = fmt.Errorf("group approvers left out, the policy file could not be read: %w", groupsErr)
	}
	if oktaErr != nil {
		groupsErr = errors.Join(groupsErr, fmt.Errorf("okta group approvers left out: %w", oktaErr))
	}
	return out, groupsErr
}

// browserOnly refuses a decision made through Slack on a flow that is
// decided in the browser only. The Slack messages of such a flow carry no
// buttons; this also covers forms opened before the setting changed.
func browserOnly(actor Identity, w *Workflow) error {
	if actor.Via == ViaSlack && w != nil && w.Slack != nil && w.Slack.BrowserOnly {
		return forbidden("approval flow %q is decided in the browser only", w.Name)
	}
	return nil
}

// loadFor is load for an action by actor: a request actor may not see is
// reported as not found, as GetRequest does, so actions do not reveal it.
func (s *Service) loadFor(ctx context.Context, actor Identity, id string) (*AccessRequest, *Workflow, error) {
	r, w, err := s.load(id)
	if r != nil && !s.CanView(ctx, actor, r) {
		return nil, nil, notFound("access request %q not found", id)
	}
	if err != nil {
		return nil, nil, err
	}
	return r, w, nil
}

// load returns copies of request id and its workflow. If the workflow is
// gone it returns the request with the error. Callers hold s.mu, so
// nothing else changes them until save.
func (s *Service) load(id string) (*AccessRequest, *Workflow, error) {
	var r *AccessRequest
	var w *Workflow
	var err error
	s.Store.View(func(d *Data) {
		var rr *AccessRequest
		var ww *Workflow
		// r comes back even when its flow is gone, so loadFor can still
		// hide it from people who may not see it.
		rr, ww, lerr := s.lookup(d, id)
		if rr != nil {
			r = clone(rr)
		}
		if lerr == nil {
			w = clone(ww)
		}
		err = lerr
	})
	return r, w, err
}

// save writes r back to the store.
func (s *Service) save(r *AccessRequest) error {
	return s.Store.Update(func(d *Data) error {
		d.Requests[r.ID] = clone(r)
		return nil
	})
}

// apiTimeout bounds one action's Tailscale API calls.
const apiTimeout = 30 * time.Second

// apiContext detaches the Tailscale API calls of an action from the caller's
// request: a closed browser tab must not abort a grant halfway, leaving the
// device and the store disagreeing.
func apiContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), apiTimeout)
}

// validVotes counts the votes on r that still count under the flow as it is
// now: the voter is still an approver, and a vote by the requester only
// counts while the flow allows self-approval.
func (s *Service) validVotes(ctx context.Context, r *AccessRequest, w *Workflow) int {
	n := 0
	for _, a := range r.Approvals {
		id := a.Identity()
		if !s.matches(ctx, w.Approvers, id) {
			continue
		}
		if isSelf(id, r.Requester) && !w.AllowSelfApproval {
			continue
		}
		n++
	}
	return n
}

// plural renders "1 approval", "2 approvals".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// sameApprover reports whether vote a was cast by actor. Tagged devices are
// matched by device ID: their display name is the device name, which the
// device can change.
func sameApprover(a Approval, actor Identity) bool {
	if actor.Tagged() {
		return a.DeviceID != "" && a.DeviceID == actor.DeviceID
	}
	return strings.EqualFold(a.Actor, actor.Actor())
}

// stale says why a pending request no longer fits its flow, or "". Requests
// are approved against the flow as it is now, not as it was at submit.
func (s *Service) stale(ctx context.Context, r *AccessRequest, w *Workflow) string {
	switch {
	case !sameGrant(r, w):
		return fmt.Sprintf("the approval flow now grants %s instead of %s; the requester should file a new request", w.grantSummary(), r.grantSummary())
	case !s.matches(ctx, w.Requesters, r.Requester):
		return "the requester is no longer allowed to request through this flow"
	}
	return ""
}

// Approve records actor's vote and, once the flow's quorum is reached, sets
// the flow's posture attribute on the target device, expiring at
// now+duration (capped at the flow's current maximum), and adds the
// requester to the flow's Okta groups.
func (s *Service) Approve(ctx context.Context, actor Identity, id, note string) (*AccessRequest, error) {
	note, err := cleanNote(note)
	if err != nil {
		return nil, err
	}
	return s.grantOutsideLock(ctx, id, func(og *groupsDone) (*AccessRequest, bool, error) {
		return s.approve(ctx, actor, id, note, og)
	})
}

// grantOutsideLock runs step, the part of an approval that holds the
// service lock (approve, or autoGrant for a flow that approves on its own).
// When step reports that it would grant and the grant includes groups, the
// providers' calls run here, without the service lock; step then runs
// again, checks everything afresh and records the outcome. groupMu is held
// until the outcome is saved, so no other grant or removal sees a half-done
// one.
func (s *Service) grantOutsideLock(ctx context.Context, id string, step func(*groupsDone) (*AccessRequest, bool, error)) (*AccessRequest, error) {
	r, needGroups, err := step(nil)
	if !needGroups {
		return r, err
	}
	s.groupMu.Lock()
	defer s.groupMu.Unlock()
	octx, cancel := apiContext(ctx)
	defer cancel()
	// Read the request again now that groupMu is held: another approval may
	// have finished, or left a note of what it added, while this one waited.
	if cur := s.Request(id); cur != nil {
		r = cur
	}
	done := s.grantGroups(octx, r)
	r, _, err = step(done)
	if !done.used {
		// The approval did not go through after all (a provider refused,
		// the request changed meanwhile, the attribute could not be set,
		// the save failed). Taking back gets its own time, per provider:
		// if the grant ran out of it, that is exactly when there is
		// something to take back.
		for _, out := range done.outs {
			tctx, tcancel := apiContext(ctx)
			s.takeBack(tctx, id, out)
			tcancel()
		}
		if cur := s.Request(id); r != nil && cur != nil {
			for _, k := range groupKinds {
				*k.adding(r) = *k.adding(cur) // what could not be taken back, if anything
			}
		}
	}
	return r, err
}

// approve is Approve under the service lock. For a grant that includes Okta
// groups it is called twice: first with og nil, when it saves nothing and
// reports needGroups, then with the outcome of the Okta calls.
func (s *Service) approve(ctx context.Context, actor Identity, id, note string, og *groupsDone) (_ *AccessRequest, needGroups bool, _ error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, w, err := s.loadFor(ctx, actor, id)
	if err != nil {
		return nil, false, err
	}
	if r.Status != StatusPending {
		return nil, false, conflict("request is %s, not pending", r.Status)
	}
	if err := browserOnly(actor, w); err != nil {
		return nil, false, err
	}
	if !s.matches(ctx, w.Approvers, actor) {
		return nil, false, forbidden("%s is not an approver in approval flow %q", actor.Actor(), w.Name)
	}
	if isSelf(actor, r.Requester) && !w.AllowSelfApproval {
		return nil, false, forbidden("approval flow %q does not allow approving your own request", w.Name)
	}
	if w.Disabled {
		return nil, false, conflict("approval flow %q is disabled; no new access can be granted", w.Name)
	}
	if why := s.stale(ctx, r, w); why != "" {
		return nil, false, conflict("%s", why)
	}
	now := s.now()
	r.ApprovalsRequired = max(1, w.ApprovalsRequired)
	r.UpdatedAt = now
	// One vote per person. A repeat click only matters when the votes
	// already meet the quorum (it was lowered, or an earlier grant failed):
	// then it grants.
	voted := slices.ContainsFunc(r.Approvals, func(a Approval) bool { return sameApprover(a, actor) })
	if !voted {
		r.Approvals = append(r.Approvals, Approval{Actor: actor.Actor(), Login: actor.Login, Tags: actor.Tags, DeviceID: actor.DeviceID, Note: note, Via: actor.Via, SlackUser: actor.SlackUser, At: now})
	}
	valid := s.validVotes(ctx, r, w)
	if valid < r.ApprovalsRequired {
		if voted {
			return r, false, nil
		}
		r.Timeline = append(r.Timeline, Event{Type: "approval", Actor: actor.Actor(), At: now, Via: actor.Via, SlackUser: actor.SlackUser,
			Note: joinNote(note, fmt.Sprintf("%d of %d approvals", valid, r.ApprovalsRequired))})
		if err := s.save(r); err != nil {
			return nil, false, err
		}
		s.emit(r, r.Timeline[len(r.Timeline)-1])
		return r, false, nil
	}
	return s.grant(ctx, r, w, Event{Actor: actor.Actor(), Via: actor.Via, SlackUser: actor.SlackUser}, note, !voted, og)
}

// grant approves r, as decided by "by" (its Actor, Via and SlackUser). For a
// request that starts later, it only records the approval: the request is
// scheduled, and startDue grants the access at its start. Otherwise it sets
// the posture attribute and records the Okta memberships now, expiring after
// r's duration (capped at the flow's current maximum; for a scheduled
// request approved after its start, at the end of its window). The Okta
// calls are not made here: when the grant includes Okta groups and og is
// nil, grant saves nothing and reports needGroups, and the caller comes back
// with their outcome (see grantOutsideLock). If granting fails, r stays
// pending with the error, and with popVote its newest vote is dropped so the
// approver can retry; grant then returns r and the error. Callers hold s.mu.
func (s *Service) grant(ctx context.Context, r *AccessRequest, w *Workflow, by Event, note string, popVote bool, og *groupsDone) (_ *AccessRequest, needGroups bool, _ error) {
	id := r.ID
	now := s.now()
	grantNote := note
	if r.Duration > w.MaxDuration {
		grantNote = joinNote(grantNote, fmt.Sprintf("shortened from %s to the flow's maximum of %s", r.Duration.Human(), w.MaxDuration.Human()))
		r.Duration = w.MaxDuration
	}
	start := now
	if r.StartAt != nil {
		start = *r.StartAt
	}
	exp := start.Add(time.Duration(r.Duration))
	if !exp.After(now) {
		return nil, false, conflict("the requested window ended at %s; the requester should file a new request", exp.Format(timeFmt))
	}
	if start.After(now) {
		// Nothing is granted yet, so nothing is added in Okta either: that
		// happens at the start, the same way an approval does it.
		r.Status, r.ApprovedAt, r.ExpiresAt, r.LastError = StatusScheduled, &now, &exp, ""
		r.Timeline = append(r.Timeline, Event{Type: "approved", Actor: by.Actor, At: now, Via: by.Via, SlackUser: by.SlackUser,
			Note: joinNote(grantNote, fmt.Sprintf("scheduled: starts %s, for %s, until %s", start.Format(timeFmt), r.Duration.Human(), exp.Format(timeFmt)))})
		if err := s.save(r); err != nil {
			return nil, false, err
		}
		s.Log.Info("access request scheduled", "id", id, "by", by.Actor, "grants", r.grantSummary(), "starts", start, "expires", exp)
		s.emit(r, r.Timeline[len(r.Timeline)-1])
		return r, false, nil
	}
	if r.wantsGroups() && og == nil {
		return r, true, nil
	}
	r.ApprovedAt = &now
	actx, cancel := apiContext(ctx)
	defer cancel()
	if err := s.applyGrant(actx, r, exp, StatusPending, og); err != nil {
		r.ApprovedAt = nil
		// Nothing was granted: drop this vote so the approver can retry.
		if popVote {
			r.Approvals = r.Approvals[:len(r.Approvals)-1]
		}
		r.LastError = err.Error()
		r.Timeline = append(r.Timeline, Event{Type: "approve_failed", Actor: by.Actor, Note: r.LastError, Via: by.Via, SlackUser: by.SlackUser, At: now})
		if serr := s.save(r); serr != nil {
			return nil, false, serr
		}
		s.Log.Info("access request approve failed", "id", id, "by", by.Actor, "err", r.LastError)
		s.emit(r, r.Timeline[len(r.Timeline)-1])
		return r, false, apiFailed("could not grant access: %s", r.LastError)
	}
	r.LastError = ""
	r.Timeline = append(r.Timeline, Event{Type: "approved", Actor: by.Actor, At: now, Via: by.Via, SlackUser: by.SlackUser,
		Note: joinNote(grantNote, fmt.Sprintf("for %s, until %s", Duration(exp.Sub(now)).Human(), exp.Format(timeFmt)))})
	if err := s.saveGranted(actx, r, StatusPending, og); err != nil {
		return nil, false, err
	}
	s.Log.Info("access request approved", "id", id, "by", by.Actor, "grants", r.grantSummary(), "expires", exp)
	s.emit(r, r.Timeline[len(r.Timeline)-1])
	return r, false, nil
}

// timeFmt is how timeline notes show a time.
const timeFmt = "2006-01-02 15:04 MST"

// applyGrant sets r's posture attribute and records its Okta memberships,
// with r approved until exp. The Okta calls were made by the caller's
// caller, outside the service lock; og is their outcome (nil when r grants
// no Okta groups). If Okta or the attribute failed, applyGrant puts the
// attribute back, puts r in failStatus with no grant recorded, and returns
// the error; the Okta memberships added for this attempt are taken back by
// grantOutsideLock. Callers hold s.mu; actx bounds the API calls.
func (s *Service) applyGrant(actx context.Context, r *AccessRequest, exp time.Time, failStatus Status, og *groupsDone) error {
	r.Status, r.ExpiresAt = StatusApproved, &exp
	if r.Attribute != "" {
		r.Attributes = []string{r.Attribute}
	}
	var err error
	attrTried := false
	if og != nil {
		err = og.err()
	}
	if err == nil && r.Attribute != "" {
		attrTried = true
		err = s.syncAttribute(actx, r.TargetDeviceID, r.Attribute, r)
	}
	if err == nil {
		if og != nil {
			// The grants are on record from here; the intents have done
			// their job.
			for _, out := range og.outs {
				*out.p.grant(r), *out.p.adding(r) = out.grant, nil
			}
		}
		return nil
	}
	// The call may have failed after Tailscale applied it (a timeout, a lost
	// response): put the attribute back to what the store says, best effort,
	// so no access is left that nobody can see.
	r.Status, r.Attributes = failStatus, nil
	for _, k := range groupKinds {
		*k.grant(r) = nil
	}
	if failStatus == StatusPending {
		r.ExpiresAt = nil
	}
	if attrTried {
		if cerr := s.syncAttribute(actx, r.TargetDeviceID, r.Attribute, r); cerr != nil {
			s.Log.Error("granting failed and the attribute could not be reset", "id", r.ID, "err", cerr)
		}
	}
	return err
}

// saveGranted reads the grant back and saves r. If the save fails, it takes
// the attribute off again, rather than leave access nobody can see or
// revoke, and puts r back in failStatus; grantOutsideLock does the same for
// the Okta memberships. Callers hold s.mu.
func (s *Service) saveGranted(actx context.Context, r *AccessRequest, failStatus Status, og *groupsDone) error {
	s.verify(actx, r)
	err := s.save(r)
	if err == nil {
		if og != nil {
			og.used = true
		}
		return nil
	}
	r.Status = failStatus
	if r.Attribute != "" {
		if derr := s.syncAttribute(actx, r.TargetDeviceID, r.Attribute, r); derr != nil {
			s.Log.Error("store write failed and the attribute could not be removed", "id", r.ID, "err", derr)
		}
	}
	return err
}

// verify reads the target device's attributes back and records whether the
// request's attribute is really there (approved) or really gone (expired,
// revoked). It never changes the request's status. It reports whether the
// outcome (confirmed, removed, or the error) changed, as opposed to only the
// time of the check. r is a copy; the caller saves it.
func (s *Service) verify(ctx context.Context, r *AccessRequest) bool {
	now := s.now()
	was := r.Enforcement
	r.Enforcement.CheckedAt = &now
	if r.Attribute == "" {
		// Groups only: a provider's add or remove has happened by the time
		// its call returns, so what jitd recorded is what is in place.
		switch {
		case r.Status == StatusApproved && r.groupsRecorded() && r.Enforcement.ConfirmedAt == nil:
			r.Enforcement.ConfirmedAt = &now
		case (r.Status == StatusExpired || r.Status == StatusRevoked) && r.Enforcement.RemovedAt == nil:
			if at := r.groupsRemovedAt(); at != nil {
				r.Enforcement.RemovedAt = at
			}
		}
		r.Enforcement.Error = r.groupsError()
		return was.ConfirmedAt != r.Enforcement.ConfirmedAt || was.RemovedAt != r.Enforcement.RemovedAt || was.Error != r.Enforcement.Error
	}
	a, err := s.TS.GetAttributes(ctx, r.TargetDeviceID)
	if errors.Is(err, tsapi.ErrUnconfigured) {
		// No credential yet (jitd is starting, or Setup needs fixing): there
		// is nothing to learn, so leave the request as it was.
		r.Enforcement = was
		return false
	}
	if err != nil {
		r.Enforcement.Error = err.Error()
	} else {
		r.Enforcement.Error = ""
		// "Present" means the API still returns it, expiry or not: Tailscale
		// drops expired attributes a little after their expiry, and that is
		// the moment access is really gone.
		v, ok := a.Attributes[r.Attribute]
		present := ok && v != nil
		switch {
		case r.Status == StatusApproved && present && r.Enforcement.ConfirmedAt == nil:
			r.Enforcement.ConfirmedAt = &now
		case (r.Status == StatusExpired || r.Status == StatusRevoked) && !present && r.Enforcement.RemovedAt == nil:
			r.Enforcement.RemovedAt = &now
		}
	}
	return was.ConfirmedAt != r.Enforcement.ConfirmedAt || was.RemovedAt != r.Enforcement.RemovedAt || was.Error != r.Enforcement.Error
}

// Decline rejects a pending request.
func (s *Service) Decline(ctx context.Context, actor Identity, id, note string) (*AccessRequest, error) {
	note, err := cleanNote(note)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, w, err := s.loadFor(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if r.Status != StatusPending {
		return nil, conflict("request is %s, not pending", r.Status)
	}
	if err := browserOnly(actor, w); err != nil {
		return nil, err
	}
	if isSelf(actor, r.Requester) {
		return nil, forbidden("you cannot decline your own request; cancel it instead")
	}
	if !s.matches(ctx, w.Approvers, actor) && !s.IsAdmin(ctx, actor) {
		return nil, forbidden("%s is not an approver in approval flow %q", actor.Actor(), w.Name)
	}
	if note == "" {
		return nil, badRequest("a reason is required to decline")
	}
	now := s.now()
	r.Status, r.UpdatedAt = StatusDeclined, now
	r.Timeline = append(r.Timeline, Event{Type: "declined", Actor: actor.Actor(), Note: note, Via: actor.Via, SlackUser: actor.SlackUser, At: now})
	if err := s.save(r); err != nil {
		return nil, err
	}
	s.Log.Info("access request declined", "id", id, "by", actor.Actor())
	s.emit(r, r.Timeline[len(r.Timeline)-1])
	return r, nil
}

// Revoke ends an approved request early. The requester, the flow's approvers
// and admins may revoke.
func (s *Service) Revoke(ctx context.Context, actor Identity, id, note string) (*AccessRequest, error) {
	note, err := cleanNote(note)
	if err != nil {
		return nil, err
	}
	r, err := s.revoke(ctx, actor, id, note)
	if err != nil || !r.anyPendingRemoval() {
		return r, err
	}
	// Group memberships come off now, without the service lock. A failure
	// does not undo the revoke: the request stays revoked and the expiry
	// tick keeps retrying the removal. The clock for a provider's calls
	// starts once groupMu is held, not while waiting for it.
	s.groupMu.Lock()
	defer s.groupMu.Unlock()
	for _, p := range s.providers() {
		octx, cancel := apiContext(ctx)
		got := s.releaseLocked(octx, p, id)
		cancel()
		if got != nil {
			r = got
		}
	}
	return r, nil
}

// revoke is Revoke under the service lock, up to the Okta removal.
func (s *Service) revoke(ctx context.Context, actor Identity, id, note string) (*AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, w, err := s.loadFor(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if r.Status != StatusApproved && r.Status != StatusScheduled {
		return nil, conflict("request is %s, not approved", r.Status)
	}
	if !isSelf(actor, r.Requester) && !s.matches(ctx, w.Approvers, actor) && !s.IsAdmin(ctx, actor) {
		return nil, forbidden("only the requester, an approver in approval flow %q or an admin can revoke", w.Name)
	}
	now := s.now()
	r.UpdatedAt = now
	if r.Status == StatusScheduled {
		// Nothing was granted yet: calling it off is only a record.
		r.Status, r.LastError = StatusRevoked, ""
		r.Timeline = append(r.Timeline, Event{Type: "revoked", Actor: actor.Actor(), Note: joinNote(note, "before it started"), Via: actor.Via, SlackUser: actor.SlackUser, At: now})
		if err := s.save(r); err != nil {
			return nil, err
		}
		s.Log.Info("scheduled access request revoked", "id", id, "by", actor.Actor())
		s.emit(r, r.Timeline[len(r.Timeline)-1])
		return r, nil
	}
	r.Status = StatusRevoked
	actx, cancel := apiContext(ctx)
	defer cancel()
	var attrErr error
	if r.Attribute != "" {
		attrErr = s.syncAttribute(actx, r.TargetDeviceID, r.Attribute, r)
	}
	if err := attrErr; err != nil {
		r.Status = StatusApproved
		r.LastError = err.Error()
		r.Timeline = append(r.Timeline, Event{Type: "revoke_failed", Actor: actor.Actor(), Note: r.LastError, Via: actor.Via, SlackUser: actor.SlackUser, At: now})
		if serr := s.save(r); serr != nil {
			return nil, serr
		}
		s.emit(r, r.Timeline[len(r.Timeline)-1])
		return r, apiFailed("could not remove access: %s", r.LastError)
	}
	r.LastError = ""
	r.Timeline = append(r.Timeline, Event{Type: "revoked", Actor: actor.Actor(), Note: note, Via: actor.Via, SlackUser: actor.SlackUser, At: now})
	s.verify(actx, r)
	if err := s.save(r); err != nil {
		return nil, err
	}
	s.Log.Info("access request revoked", "id", id, "by", actor.Actor())
	s.emit(r, r.Timeline[len(r.Timeline)-1])
	return r, nil
}

// Cancel withdraws a pending request. Only the requester may cancel (others
// decline); nothing was granted yet, so no API call is needed.
func (s *Service) Cancel(ctx context.Context, actor Identity, id, note string) (*AccessRequest, error) {
	note, err := cleanNote(note)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, w, err := s.loadFor(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if r.Status != StatusPending {
		return nil, conflict("request is %s, not pending", r.Status)
	}
	if !isSelf(actor, r.Requester) {
		return nil, forbidden("only the requester can cancel a request for %q; approvers and admins decline instead", w.Name)
	}
	now := s.now()
	r.Status, r.UpdatedAt = StatusCancelled, now
	r.Timeline = append(r.Timeline, Event{Type: "cancelled", Actor: actor.Actor(), Note: note, Via: actor.Via, SlackUser: actor.SlackUser, At: now})
	if err := s.save(r); err != nil {
		return nil, err
	}
	s.Log.Info("access request cancelled", "id", id, "by", actor.Actor())
	s.emit(r, r.Timeline[len(r.Timeline)-1])
	return r, nil
}

// ExpireDue marks approved requests whose expiry has passed as expired, and
// pending requests nobody decided within the workflow's approval timeout. It
// makes no Tailscale API calls: Tailscale removes the attribute itself at its
// expiry. Group memberships have no expiry, so it removes those, after the
// service lock is released (see groupUpkeep).
// (Two live requests for one attribute and device are rare: one per flow and
// device is allowed, so it takes an attribute moved to another flow. The
// attribute then carries the later expiry already.)
func (s *Service) ExpireDue() int {
	s.startDue()
	n := s.expireDue()
	s.groupUpkeep(context.Background())
	return n
}

// expireDue is ExpireDue under the service lock, without the Okta removals.
func (s *Service) expireDue() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var expired []*AccessRequest
	err := s.Store.Update(func(d *Data) error {
		expired = nil
		for _, r := range d.Requests {
			switch {
			case r.Status == StatusApproved && r.ExpiresAt != nil && !r.ExpiresAt.After(now):
				r.Status, r.UpdatedAt = StatusExpired, now
				r.Timeline = append(r.Timeline, Event{Type: "expired", Actor: "system", At: now})
				expired = append(expired, clone(r))
			case r.Status == StatusScheduled && r.ExpiresAt != nil && !r.ExpiresAt.After(now):
				// Its window passed without access ever starting (every
				// attempt failed, or jitd was down for all of it).
				r.Status, r.UpdatedAt = StatusExpired, now
				r.Timeline = append(r.Timeline, Event{Type: "expired", Actor: "system", Note: "the scheduled window ended before access could start", At: now})
				expired = append(expired, clone(r))
			case r.Status == StatusPending:
				timeout := DefaultApprovalTimeout
				w, ok := d.Workflows[r.WorkflowID]
				if ok && w.ApprovalTimeout > 0 {
					timeout = w.ApprovalTimeout
				}
				if ok && w.AutoApprove && !s.autoBusy[r.ID] {
					// jitd stopped between saving the request and
					// granting it. Nobody may be able to approve it, and
					// while it is pending the requester cannot file
					// another, so it does not wait out the timeout.
					r.Status, r.UpdatedAt = StatusExpired, now
					r.Timeline = append(r.Timeline, Event{Type: "expired", Actor: "system", At: now,
						Note: "the automatic approval did not finish (jitd was stopped meanwhile); file a new request"})
					expired = append(expired, clone(r))
					continue
				}
				if r.StartAt != nil {
					// A request scheduled ahead stays open for a decision
					// until its window ends, however far ahead it was
					// filed: the flow's approval timeout is for requests
					// that start on approval.
					if !r.StartAt.Add(time.Duration(r.Duration)).After(now) {
						r.Status, r.UpdatedAt = StatusExpired, now
						r.Timeline = append(r.Timeline, Event{Type: "expired", Actor: "system", Note: "no decision before the requested window ended", At: now})
						expired = append(expired, clone(r))
					}
					continue
				}
				if !r.CreatedAt.Add(time.Duration(timeout)).After(now) {
					r.Status, r.UpdatedAt = StatusExpired, now
					r.Timeline = append(r.Timeline, Event{Type: "expired", Actor: "system", Note: fmt.Sprintf("no decision within %s", timeout), At: now})
					expired = append(expired, clone(r))
				}
			}
		}
		if len(expired) == 0 {
			return errNoChange // the usual tick: skip comparing every row
		}
		return nil
	})
	if err != nil {
		s.Log.Error("expiring requests", "err", err)
		return 0
	}
	ids := make([]string, 0, len(expired))
	for _, r := range expired {
		ids = append(ids, r.ID)
		s.Log.Info("access request expired", "id", r.ID)
		s.emit(r, r.Timeline[len(r.Timeline)-1])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s.verifyRemovals(ctx)
	return len(ids)
}

// startBatch caps how many scheduled requests one tick starts; the rest
// start on the next tick.
const startBatch = 20

// startDue grants the access of scheduled requests whose start has come.
// Each one goes through grantOutsideLock, the way an approval does: the
// service lock is held for one request at a time, and the Okta calls are
// made without it, after the memberships to add are on record. The caller
// must not hold mu.
func (s *Service) startDue() {
	now := s.now()
	var due []*AccessRequest
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.dueToStart(now) {
				due = append(due, clone(r))
			}
		}
	})
	slices.SortFunc(due, func(a, b *AccessRequest) int { return a.StartAt.Compare(*b.StartAt) })
	if len(due) > startBatch {
		due = due[:startBatch]
	}
	ctx := context.Background()
	for _, r := range due {
		id := r.ID
		// start records and logs the outcome; there is nobody to tell here.
		_, _ = s.grantOutsideLock(ctx, id, func(og *groupsDone) (*AccessRequest, bool, error) {
			return s.start(ctx, id, og)
		})
	}
}

// dueToStart reports whether r is scheduled and inside its window.
func (r *AccessRequest) dueToStart(now time.Time) bool {
	return r.Status == StatusScheduled && r.StartAt != nil && !r.StartAt.After(now) && r.ExpiresAt != nil && r.ExpiresAt.After(now)
}

// start starts one scheduled request, under the service lock. A request
// whose flow changed (it now grants something else, or the requester may no
// longer request through it) or was disabled or deleted is called off
// instead. If granting fails, the request stays scheduled with the error
// and is tried again on every tick until its window ends. Like approve, it
// is called twice for a grant that includes Okta groups: first with og nil,
// when it saves nothing and reports needGroups, then with the outcome of the
// Okta calls, when it checks everything afresh.
func (s *Service) start(ctx context.Context, id string, og *groupsDone) (_ *AccessRequest, needGroups bool, _ error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	r := s.Request(id)
	if r == nil || !r.dueToStart(now) {
		return nil, false, nil // revoked, started or ended meanwhile
	}
	r.UpdatedAt = now
	w, err := s.GetWorkflow(r.WorkflowID)
	why := ""
	switch {
	case err != nil:
		why = "its approval flow was deleted"
	case w.Disabled:
		why = "its approval flow was disabled"
	default:
		why = s.stale(ctx, r, w)
	}
	if why != "" {
		r.Status, r.LastError = StatusRevoked, ""
		r.Timeline = append(r.Timeline, Event{Type: "revoked", Actor: "system", Note: "not started: " + why, At: now})
		if err := s.save(r); err != nil {
			s.Log.Error("calling off a scheduled request", "id", r.ID, "err", err)
			return nil, false, err
		}
		s.Log.Info("scheduled access request called off", "id", r.ID, "why", why)
		s.emit(r, r.Timeline[len(r.Timeline)-1])
		return r, false, nil
	}
	if r.wantsGroups() && og == nil {
		return r, true, nil
	}
	actx, cancel := apiContext(ctx)
	defer cancel()
	exp := *r.ExpiresAt
	if err := s.applyGrant(actx, r, exp, StatusScheduled, og); err != nil {
		msg := err.Error()
		if msg != r.LastError { // one timeline entry per distinct failure, not one per tick
			r.Timeline = append(r.Timeline, Event{Type: "start_failed", Actor: "system", Note: msg + "; retrying until the window ends", At: now})
		}
		r.LastError = msg
		if serr := s.save(r); serr != nil {
			s.Log.Error("recording a failed scheduled start", "id", r.ID, "err", serr)
			return nil, false, serr
		}
		s.Log.Info("scheduled access request could not start; will retry", "id", r.ID, "err", msg)
		s.emit(r, r.Timeline[len(r.Timeline)-1])
		return r, false, err
	}
	r.LastError = ""
	r.Timeline = append(r.Timeline, Event{Type: "started", Actor: "system", At: now,
		Note: fmt.Sprintf("scheduled access started, for %s, until %s", Duration(exp.Sub(now)).Human(), exp.Format(timeFmt))})
	if err := s.saveGranted(actx, r, StatusScheduled, og); err != nil {
		s.Log.Error("starting a scheduled request", "id", r.ID, "err", err)
		return nil, false, err
	}
	s.Log.Info("scheduled access request started", "id", r.ID, "grants", r.grantSummary(), "expires", exp)
	s.emit(r, r.Timeline[len(r.Timeline)-1])
	return r, false, nil
}

// verifyBatch caps how many ended requests one expiry tick reads back, so a
// slow Tailscale API cannot hold the service lock for long.
const verifyBatch = 10

// verifyRemovals reads back the attributes of requests that ended recently
// and are not yet confirmed gone. Tailscale removes expired attributes a
// little after their expiry, so this usually confirms within a minute or two.
// The API calls run outside the store lock; only changed outcomes are saved.
func (s *Service) verifyRemovals(ctx context.Context) {
	now := s.now()
	var due []*AccessRequest
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.awaitingRemoval(now) {
				due = append(due, clone(r))
			}
		}
	})
	if len(due) > verifyBatch {
		due = due[:verifyBatch]
	}
	var checked []*AccessRequest
	was := map[string]Enforcement{}
	changed := false
	for _, r := range due {
		if ctx.Err() != nil {
			break
		}
		was[r.ID] = r.Enforcement
		changed = s.verify(ctx, r) || changed
		checked = append(checked, r)
	}
	if len(checked) == 0 {
		return
	}
	err := s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		for _, r := range checked {
			if cur, ok := d.Requests[r.ID]; ok {
				cur.Enforcement = r.Enforcement
			}
		}
		return changed, nil
	})
	if err != nil {
		s.Log.Error("verifying attribute removal", "err", err)
		return
	}
	for _, r := range checked {
		s.emitVerified(r, was[r.ID])
	}
}

// RecheckWindow is how long after a request ends jitd keeps reading the
// device back to confirm the attribute is gone.
const RecheckWindow = 24 * time.Hour

// awaitingRemoval reports whether r ended recently with access granted and
// the attribute has not yet been seen gone.
func (r *AccessRequest) awaitingRemoval(now time.Time) bool {
	ended := r.Status == StatusExpired || r.Status == StatusRevoked
	return ended && len(r.Attributes) > 0 && r.Enforcement.RemovedAt == nil && now.Sub(r.UpdatedAt) < RecheckWindow
}

// Unconfirmed reports whether r's enforcement is still worth reading back:
// approved but not yet seen on the device, or ended but not yet seen gone.
func (r *AccessRequest) Unconfirmed(now time.Time) bool {
	return (r.Status == StatusApproved && r.Enforcement.ConfirmedAt == nil) || r.awaitingRemoval(now)
}

// VerifyNow re-reads the device attributes for one request (e.g. when its
// page is opened and it is not yet confirmed).
func (s *Service) VerifyNow(ctx context.Context, viewer Identity, id string) (*AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.GetRequest(ctx, viewer, id)
	if err != nil {
		return nil, err
	}
	was := r.Enforcement
	changed := s.verify(ctx, r)
	err = s.Store.UpdateQuiet(func(d *Data) (bool, error) {
		cur, ok := d.Requests[id]
		if !ok {
			return false, notFound("access request %q not found", id)
		}
		cur.Enforcement = r.Enforcement
		return changed, nil
	})
	if err == nil {
		s.emitVerified(r, was)
	}
	return r, err
}

// Allowed says which actions actor may take on r right now (for the UI; the
// action methods re-check).
type Allowed struct {
	Approve, Decline, Revoke, Cancel bool
	Why                              string // why approve is not allowed, if pending
}

// Permissions computes Allowed for actor on r.
func (s *Service) Permissions(ctx context.Context, actor Identity, r *AccessRequest) Allowed {
	var a Allowed
	w, err := s.GetWorkflow(r.WorkflowID)
	if err != nil {
		a.Why = "the approval flow no longer exists"
		return a
	}
	approver := s.matches(ctx, w.Approvers, actor)
	admin := s.IsAdmin(ctx, actor)
	switch r.Status {
	case StatusPending:
		a.Decline = (approver || admin) && !isSelf(actor, r.Requester)
		a.Cancel = isSelf(actor, r.Requester)
		switch {
		case !approver:
			a.Why = "you are not an approver in this flow"
		case w.Disabled:
			a.Why = "this approval flow is disabled; no new access can be granted"
		case isSelf(actor, r.Requester) && !w.AllowSelfApproval:
			a.Why = "this flow does not allow approving your own request"
		case slices.ContainsFunc(r.Approvals, func(x Approval) bool { return sameApprover(x, actor) }) && s.validVotes(ctx, r, w) < max(1, w.ApprovalsRequired):
			a.Why = "you already approved it; it needs another approver"
		default:
			if why := s.stale(ctx, r, w); why != "" {
				a.Why = why
			} else {
				a.Approve = true
			}
		}
	case StatusApproved, StatusScheduled:
		a.Revoke = approver || isSelf(actor, r.Requester) || admin
	}
	return a
}

// syncAttribute makes the attribute key on device match what should be
// there: present with the latest expiry among approved, unexpired requests
// that set it, or absent if there are none. self is the request being
// changed (its new status counts, not the stored one). The store is only
// read; the API call runs without its lock.
func (s *Service) syncAttribute(ctx context.Context, device, key string, self *AccessRequest) error {
	now := s.now()
	live := func(r *AccessRequest) bool {
		return r.Status == StatusApproved && r.TargetDeviceID == device && r.ExpiresAt != nil && r.ExpiresAt.After(now) && slices.Contains(r.Attributes, key)
	}
	var latest time.Time
	var ids []string
	add := func(r *AccessRequest) {
		ids = append(ids, r.ID)
		if r.ExpiresAt.After(latest) {
			latest = *r.ExpiresAt
		}
	}
	s.Store.View(func(d *Data) {
		for _, r := range d.Requests {
			if r.ID != self.ID && live(r) {
				add(r)
			}
		}
	})
	if live(self) {
		add(self)
	}
	if len(ids) == 0 {
		err := s.TS.DeleteAttribute(ctx, device, key)
		if tsapi.IsNotFound(err) {
			return nil
		}
		return err
	}
	slices.Sort(ids)
	return s.TS.SetAttribute(ctx, device, key, true, latest, "jitd "+strings.Join(ids, ","))
}

func (s *Service) lookup(d *Data, id string) (*AccessRequest, *Workflow, error) {
	r, ok := d.Requests[id]
	if !ok {
		return nil, nil, notFound("access request %q not found", id)
	}
	w, ok := d.Workflows[r.WorkflowID]
	if !ok {
		return r, nil, conflict("approval flow %q of request %s no longer exists", r.WorkflowID, id)
	}
	return r, w, nil
}

// isLive reports whether r is pending, scheduled or approved and not yet
// expired.
func (r *AccessRequest) isLive(now time.Time) bool {
	switch r.Status {
	case StatusPending:
		return true
	case StatusApproved, StatusScheduled:
		return r.ExpiresAt != nil && r.ExpiresAt.After(now)
	}
	return false
}

// window is when r gives (or would give) access: from its start (its
// scheduled start, its approval, or now for a pending request that starts
// on approval) to its end.
func (r *AccessRequest) window(now time.Time) (start, end time.Time) {
	switch {
	case r.StartAt != nil:
		start = *r.StartAt
	case r.ApprovedAt != nil:
		start = *r.ApprovedAt
	default:
		start = now
	}
	if r.ExpiresAt != nil {
		return start, *r.ExpiresAt
	}
	return start, start.Add(time.Duration(r.Duration))
}

// isSelf reports whether a and b are the same requester: the same user, or,
// for tagged devices, the same device.
func isSelf(a, b Identity) bool {
	if a.Tagged() || b.Tagged() {
		return a.DeviceID != "" && a.DeviceID == b.DeviceID
	}
	return a.Login != "" && strings.EqualFold(a.Login, b.Login)
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + " (" + b + ")"
}
