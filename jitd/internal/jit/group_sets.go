package jit

import "slices"

// GroupSet is the groups of one kind (Okta, Google) on a request or a
// flow, for showing them.
type GroupSet struct {
	Key    string     // "okta", "google"
	Label  string     // "Okta", "Google"
	Groups []GroupRef // what the flow grants
	// Grant is what jitd did about them on a request; nil on a flow, and
	// until an approval got that far.
	Grant *GroupGrant

	k *groupKind
	r *AccessRequest
}

// GroupSets lists the kinds of group the flow grants.
func (w *Workflow) GroupSets() []GroupSet {
	var out []GroupSet
	for _, k := range groupKinds {
		if gs := *k.flowGroups(w); len(gs) > 0 {
			out = append(out, GroupSet{Key: k.key, Label: k.label, Groups: gs, k: k})
		}
	}
	return out
}

// GroupSets lists the kinds of group the request is about: the ones it
// asks for, and any jitd has a record for.
func (r *AccessRequest) GroupSets() []GroupSet {
	var out []GroupSet
	for _, k := range groupKinds {
		if gs, g := k.groups(r), k.granted(r); len(gs) > 0 || g != nil {
			out = append(out, GroupSet{Key: k.key, Label: k.label, Groups: gs, Grant: g, k: k, r: r})
		}
	}
	return out
}

// GroupsStuck reports whether removing r's memberships, of any kind, has
// been failing for long enough that jitd told the admins.
func (r *AccessRequest) GroupsStuck() bool {
	for _, k := range groupKinds {
		if k.stuckOn(r) {
			return true
		}
	}
	return false
}

// GroupsRemovalPending reports whether r ended and its requester is still
// in groups, of any kind, that jitd added them to.
func (r *AccessRequest) GroupsRemovalPending() bool { return r.anyPendingRemoval() }

// Labels names the set's groups.
func (g GroupSet) Labels() []string { return groupLabels(g.Groups) }

// RemovalPending reports whether the request ended and its requester is
// still in groups of this kind that jitd added them to.
func (g GroupSet) RemovalPending() bool { return g.r != nil && g.k.pendingRemoval(g.r) }

// Stuck reports whether removing them has been failing for long enough
// that jitd told the admins.
func (g GroupSet) Stuck() bool { return g.r != nil && g.k.stuckOn(g.r) }

func (g GroupSet) removed() bool { return g.r != nil && g.Grant != nil && g.Grant.RemovedAt != nil }

func (g GroupSet) names(ids []string) []string {
	if g.r == nil {
		return nil
	}
	return g.k.labels(g.r, ids)
}

// Kept names the groups the requester stayed in when the request ended,
// because another running request holds them.
func (g GroupSet) Kept() []string {
	if !g.removed() {
		return nil
	}
	return g.names(g.Grant.Kept)
}

// Removed names the groups jitd took the requester out of when the request
// ended.
func (g GroupSet) Removed() []string {
	if !g.removed() {
		return nil
	}
	var ids []string
	for _, id := range g.Grant.Added {
		if !slices.Contains(g.Grant.Kept, id) {
			ids = append(ids, id)
		}
	}
	return g.names(ids)
}

// Added names the groups jitd added the requester to.
func (g GroupSet) Added() []string {
	if g.Grant == nil {
		return nil
	}
	return g.names(g.Grant.Added)
}

// Missing names the groups the requester was taken out of, outside jitd,
// while the access was running.
func (g GroupSet) Missing() []string {
	if g.Grant == nil || g.r == nil || g.r.Status != StatusApproved {
		return nil
	}
	return g.names(g.Grant.Missing)
}
