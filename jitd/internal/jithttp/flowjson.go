package jithttp

import (
	"net/http"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

// flowJSON is an approval flow as /v1/workflows reads and writes it. What
// an approval grants sits under "grants", one key per kind, so that a new
// kind is one more key. The store, the pages and Slack use jit.Workflow,
// whose layout is older: the attribute at the top, the groups beside it.
//
// Every field of jit.Workflow has one here; TestFlowJSONCoversWorkflow
// fails when one is added there and not here.
type flowJSON struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	Description       string             `json:"description,omitempty"`
	Grants            *flowGrants        `json:"grants,omitempty"`
	Requesters        []jit.Principal    `json:"requesters"`
	Approvers         []jit.Principal    `json:"approvers"`
	AllowSelfApproval bool               `json:"allow_self_approval"`
	AutoApprove       bool               `json:"auto_approve,omitempty"`
	AutoApproveBy     string             `json:"auto_approve_by,omitempty"`
	AutoApproveAt     *time.Time         `json:"auto_approve_at,omitempty"`
	UpdatedBy         string             `json:"updated_by,omitempty"`
	MaxDuration       jit.Duration       `json:"max_duration"`
	ApprovalTimeout   jit.Duration       `json:"approval_timeout,omitempty"`
	ApprovalsRequired int                `json:"approvals_required,omitempty"`
	DefaultDuration   jit.Duration       `json:"default_duration,omitempty"`
	Disabled          bool               `json:"disabled,omitempty"`
	Slack             *jit.WorkflowSlack `json:"slack,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`

	// The layout before "grants". Still read, so that what was written
	// against it keeps working; never written.
	Attribute    *string        `json:"attribute,omitempty"`
	OktaGroups   []jit.GroupRef `json:"okta_groups,omitempty"`
	GoogleGroups []jit.GroupRef `json:"google_groups,omitempty"`
	Resources    []jit.Resource `json:"resources,omitempty"`
}

// flowGrants is what an approval grants. A kind that is left out, or is
// there with nothing in it, is not granted.
type flowGrants struct {
	Tailscale *tailscaleGrant `json:"tailscale,omitempty"`
	Okta      *groupsGrant    `json:"okta,omitempty"`
	Google    *groupsGrant    `json:"google,omitempty"`
}

// tailscaleGrant is access over Tailscale: the posture attribute an
// approval sets, and what the admin says it gives access to.
type tailscaleGrant struct {
	Attribute string         `json:"attribute"`
	Resources []jit.Resource `json:"resources"`
}

// groupsGrant is the groups of one provider an approval adds the requester
// to.
type groupsGrant struct {
	Groups []jit.GroupRef `json:"groups"`
}

// flowOut is w as the API shows it.
func flowOut(w *jit.Workflow) *flowJSON {
	g := &flowGrants{}
	// A flow from before "grants" may list what it gives access to without
	// setting an attribute; it is shown as it is, so that it can be saved
	// back unchanged.
	if w.Attribute != "" || len(w.Resources) > 0 {
		g.Tailscale = &tailscaleGrant{Attribute: w.Attribute, Resources: jit.OrEmpty(w.Resources)}
	}
	if len(w.OktaGroups) > 0 {
		g.Okta = &groupsGrant{Groups: w.OktaGroups}
	}
	if len(w.GoogleGroups) > 0 {
		g.Google = &groupsGrant{Groups: w.GoogleGroups}
	}
	return &flowJSON{
		ID: w.ID, Name: w.Name, Description: w.Description, Grants: g,
		Requesters: w.Requesters, Approvers: w.Approvers, AllowSelfApproval: w.AllowSelfApproval,
		AutoApprove: w.AutoApprove, AutoApproveBy: w.AutoApproveBy, AutoApproveAt: w.AutoApproveAt, UpdatedBy: w.UpdatedBy,
		MaxDuration: w.MaxDuration, ApprovalTimeout: w.ApprovalTimeout, ApprovalsRequired: w.ApprovalsRequired,
		DefaultDuration: w.DefaultDuration, Disabled: w.Disabled, Slack: w.Slack,
		CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt,
	}
}

// flowsOut is flowOut for a list.
func flowsOut(ws []*jit.Workflow) []*flowJSON {
	out := make([]*flowJSON, len(ws))
	for i, w := range ws {
		out[i] = flowOut(w)
	}
	return out
}

// workflow is the flow a request body describes. What it grants comes from
// "grants" or from the older top-level fields; a body with both is refused,
// since nobody can tell which one was meant.
func (f *flowJSON) workflow() (jit.Workflow, error) {
	w := jit.Workflow{
		ID: f.ID, Name: f.Name, Description: f.Description,
		Requesters: f.Requesters, Approvers: f.Approvers, AllowSelfApproval: f.AllowSelfApproval,
		AutoApprove: f.AutoApprove, AutoApproveBy: f.AutoApproveBy, AutoApproveAt: f.AutoApproveAt, UpdatedBy: f.UpdatedBy,
		MaxDuration: f.MaxDuration, ApprovalTimeout: f.ApprovalTimeout, ApprovalsRequired: f.ApprovalsRequired,
		DefaultDuration: f.DefaultDuration, Disabled: f.Disabled, Slack: f.Slack,
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt,
	}
	older := f.Attribute != nil || f.OktaGroups != nil || f.GoogleGroups != nil || f.Resources != nil
	switch g := f.Grants; {
	case g != nil && older:
		return w, &jit.Error{Code: "bad_request", Status: http.StatusBadRequest,
			Message: `say what an approval grants under "grants", or in the older top-level fields (attribute, resources, okta_groups, google_groups), not in both`}
	case g != nil:
		if g.Tailscale != nil {
			w.Attribute, w.Resources = g.Tailscale.Attribute, g.Tailscale.Resources
		}
		if g.Okta != nil {
			w.OktaGroups = g.Okta.Groups
		}
		if g.Google != nil {
			w.GoogleGroups = g.Google.Groups
		}
	default:
		if f.Attribute != nil {
			w.Attribute = *f.Attribute
		}
		w.OktaGroups, w.GoogleGroups, w.Resources = f.OktaGroups, f.GoogleGroups, f.Resources
	}
	return w, nil
}
