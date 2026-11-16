// Package jit implements just-in-time access requests for Tailscale Services:
// approval workflows, access requests, and granting access by setting a custom
// device posture attribute (with an expiry) through the Tailscale API.
package jit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Principal names who may request or approve: a user login
// ("alice@example.com"), a device tag ("tag:x"), a policy-file group
// ("group:x"), an Okta group ("okta:Name" or "okta:00g…"), or
// "autogroup:member" (any user, not tagged devices).
type Principal string

const AutogroupMember Principal = "autogroup:member"

// Status is the lifecycle state of an access request.
type Status string

const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusDeclined  Status = "declined"
	StatusExpired   Status = "expired"
	StatusRevoked   Status = "revoked"
	StatusCancelled Status = "cancelled" // withdrawn by the requester while pending
)

// Duration is a time.Duration that encodes to JSON as "1h30m0s" and decodes
// from either a duration string (Go syntax plus days: "90m", "2h", "3d",
// "1d12h") or a number of nanoseconds.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*d = 0
			return nil
		}
		v, err := ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string like \"30m\" or a number of nanoseconds")
	}
	*d = Duration(n)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }

// Human renders a duration for people: "1 hour", "7 days", "45 minutes",
// "1 day 12 hours", "1 hour 30 minutes".
func (d Duration) Human() string {
	t := time.Duration(d)
	if t <= 0 {
		return "-"
	}
	var parts []string
	for _, u := range []struct {
		size time.Duration
		word string
	}{{24 * time.Hour, "day"}, {time.Hour, "hour"}, {time.Minute, "minute"}} {
		if n := t / u.size; n > 0 {
			parts = append(parts, plural(int(n), u.word))
			t -= n * u.size
		}
	}
	if len(parts) == 0 {
		return t.String() // under a minute
	}
	return strings.Join(parts, " ")
}

// ParseDuration is time.ParseDuration plus a leading whole number of days
// ("3d", "1d12h", "2d30m"). Signs are refused: durations here are always
// positive amounts of time.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	bad := fmt.Errorf("invalid duration %q: use e.g. 30m, 2h, 3d or 1d12h", s)
	if s == "" || strings.ContainsAny(s, "+-") {
		return 0, bad
	}
	days, rest, ok := strings.Cut(s, "d")
	if !ok {
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, bad
		}
		return d, nil
	}
	n, err := strconv.Atoi(days)
	if err != nil || n > 3650 {
		return 0, bad
	}
	out := time.Duration(n) * 24 * time.Hour
	if rest != "" {
		r, err := time.ParseDuration(rest)
		if err != nil || r > math.MaxInt64-out {
			return 0, bad
		}
		out += r
	}
	return out, nil
}

// Workflow is an approval flow: who may request it, who approves, and what
// an approval grants: a posture attribute on the requester's device, time
// limited membership in Okta groups, or both.
type Workflow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Attribute is the custom posture attribute an approval sets, with an
	// expiry, on the requester's device: custom:jit_<name>. It is the only
	// thing jitd does; what it unlocks is decided by the tailnet policy
	// (grants with srcPosture on posture:jit_<name>).
	//
	// It may be empty when the flow grants Okta groups instead.
	Attribute string `json:"attribute"`
	// OktaGroups are the Okta groups an approval adds the requester (the
	// Okta user with their login or email) to, until the access ends. Okta
	// has no expiring membership, so jitd removes them itself: unlike the
	// posture attribute, this needs jitd running to end on time.
	OktaGroups []OktaGroup `json:"okta_groups,omitempty"`
	// Resources is "Gives access to": what the policy unlocks for this
	// attribute, as told by the admin. Discovery only, for people and agents
	// choosing what to request; it grants nothing.
	Resources         []Resource  `json:"resources"`
	Requesters        []Principal `json:"requesters"`
	Approvers         []Principal `json:"approvers"`
	AllowSelfApproval bool        `json:"allow_self_approval"`
	MaxDuration       Duration    `json:"max_duration"`
	// ApprovalTimeout is how long a request may stay pending before it
	// expires undecided. Zero means DefaultApprovalTimeout.
	ApprovalTimeout Duration `json:"approval_timeout,omitempty"`
	// ApprovalsRequired is how many distinct approvers must approve before
	// access is granted. Zero means 1.
	ApprovalsRequired int `json:"approvals_required,omitempty"`
	// DefaultDuration is preselected when requesting. Zero means the smaller
	// of one hour and MaxDuration.
	DefaultDuration Duration `json:"default_duration,omitempty"`
	// Disabled stops new requests and approvals; existing access runs out
	// on its own.
	Disabled bool `json:"disabled,omitempty"`
	// Slack is where requests through this flow are announced, if Slack is
	// connected. Nil means nowhere.
	Slack     *WorkflowSlack `json:"slack,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// WorkflowSlack is a flow's Slack settings.
type WorkflowSlack struct {
	Channel     string `json:"channel,omitempty"`      // channel ID (C…/G…) new requests are posted to
	ChannelName string `json:"channel_name,omitempty"` // its name when it was picked, for display
	DMApprovers bool   `json:"dm_approvers,omitempty"` // also send each approver a direct message
	// BrowserOnly leaves the Approve and Decline buttons off the Slack
	// messages: decisions for this flow are made in the browser, where the
	// approver is identified by Tailscale, not by their Slack account.
	BrowserOnly bool `json:"browser_only,omitempty"`
}

// SlackMessage is one message jitd posted about a request, so it can be
// updated as the request moves on.
type SlackMessage struct {
	Channel string `json:"channel"`        // channel or DM conversation ID
	TS      string `json:"ts"`             // the message's timestamp, Slack's message ID
	Kind    string `json:"kind,omitempty"` // "channel" or "dm"
	User    string `json:"user,omitempty"` // the Slack user a DM went to
}

// Resource is one thing an attribute gives access to, as a policy grant
// destination (svc:mysql-prod, tag:prod-db, a host name, a CIDR) plus a
// description for whoever is choosing what to request.
type Resource struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// OktaGroup names one Okta group a flow grants membership in. When a flow
// is saved, a group given by Name alone is looked up and its ID filled in;
// the ID is what jitd uses from then on.
type OktaGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Label is how the group is shown.
func (g OktaGroup) Label() string {
	if g.Name != "" {
		return g.Name
	}
	return g.ID
}

// OktaGrant is what an approval did in Okta for one request: which user it
// acted on and which group memberships jitd added (and so must remove).
type OktaGrant struct {
	UserID string `json:"user_id"`
	Login  string `json:"login,omitempty"` // the Okta login, for people
	// Added are the IDs of the groups jitd made the user a member of (or
	// that another live jitd request had already added). These come off
	// when the access ends.
	Added []string `json:"added,omitempty"`
	// Preexisting are groups the user was already in, outside jitd, when
	// access was approved. jitd never removes these.
	Preexisting []string `json:"preexisting,omitempty"`
	// RemovedAt is when every Added membership was confirmed removed
	// after the request ended.
	RemovedAt *time.Time `json:"removed_at,omitempty"`
	// Error is the last failure to remove a membership; jitd keeps retrying.
	Error string `json:"error,omitempty"`
}

// AttrPrefix is the namespace of every attribute jitd writes.
const AttrPrefix = "custom:jit_"

// ReservedAttribute is the name (after AttrPrefix) the setup check writes on
// jitd's own node; no flow may use it.
const ReservedAttribute = "selfcheck"

// MaxFlowDuration caps a flow's maximum and default request duration and
// its approval timeout, so a typo cannot become near-permanent access.
const MaxFlowDuration = Duration(365 * 24 * time.Hour)

// MaxApprovalsRequired caps a flow's quorum (the flow form offers 1..this).
const MaxApprovalsRequired = 10

// Posture is the policy-file posture that checks the workflow's attribute,
// or "" if the flow sets none.
func (w *Workflow) Posture() string {
	if w.Attribute == "" {
		return ""
	}
	return PostureFor(w.Attribute)
}

// OktaGroupLabels lists the flow's Okta group names.
func (w *Workflow) OktaGroupLabels() []string { return oktaLabels(w.OktaGroups) }

func oktaLabels(gs []OktaGroup) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.Label()
	}
	return out
}

// oktaGroupIDs lists the group IDs, sorted, for comparing two sets.
func oktaGroupIDs(gs []OktaGroup) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.ID)
	}
	slices.Sort(out)
	return out
}

// PostureFor turns custom:jit_x into posture:jit_x.
func PostureFor(attr string) string { return "posture:jit_" + strings.TrimPrefix(attr, AttrPrefix) }

// ResourceNames lists the resource names.
func (w *Workflow) ResourceNames() []string { return resourceNames(w.Resources) }

func resourceNames(rs []Resource) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

// DefaultMaxDuration applies when a workflow does not set one.
const DefaultMaxDuration = Duration(time.Hour)

// DefaultApprovalTimeout applies when a workflow does not set one.
const DefaultApprovalTimeout = Duration(24 * time.Hour)

// Identity is who is calling, as reported by tailscaled WhoIs.
type Identity struct {
	Login       string   `json:"login"`
	DisplayName string   `json:"display_name,omitempty"`
	DeviceID    string   `json:"device_id"`
	DeviceName  string   `json:"device_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	// Via says how the caller was identified when it was not Tailscale:
	// "slack" for a Slack user matched to this login by email. Recorded with
	// every decision they make.
	Via string `json:"via,omitempty"`
	// SlackUser is the Slack account behind a Via "slack" identity, as
	// "<team ID>/<user ID>", so a decision can be traced to the account that
	// made it even if that account's email changes later.
	SlackUser string `json:"slack_user,omitempty"`
}

// ViaSlack marks identities that came from a Slack account, not WhoIs.
const ViaSlack = "slack"

// Tagged reports whether the caller is a tagged device (no user identity).
func (id Identity) Tagged() bool { return len(id.Tags) > 0 }

// Actor is how an identity is shown in a timeline.
func (id Identity) Actor() string {
	if id.Tagged() {
		return strings.Join(id.Tags, ",") + " (" + id.DeviceName + ")"
	}
	return id.Login
}

// Approval is one approver's vote on a request.
type Approval struct {
	Actor     string    `json:"actor"`
	Login     string    `json:"login,omitempty"`     // with Tags, who voted, to re-check against the flow
	Tags      []string  `json:"tags,omitempty"`      // the voter's tags, for tagged devices
	DeviceID  string    `json:"device_id,omitempty"` // tells tagged approvers apart (their name can change)
	Note      string    `json:"note,omitempty"`
	Via       string    `json:"via,omitempty"`        // "slack" when the vote came through Slack
	SlackUser string    `json:"slack_user,omitempty"` // with Via "slack": "<team>/<user>"
	At        time.Time `json:"at"`
}

// Identity is who cast the vote, as far as matching principals goes.
func (a Approval) Identity() Identity {
	login := a.Login
	if login == "" && len(a.Tags) == 0 && strings.Contains(a.Actor, "@") {
		login = a.Actor // votes stored before Login existed
	}
	return Identity{Login: login, Tags: a.Tags, DeviceID: a.DeviceID}
}

// Enforcement is what jitd has verified on the device through the Tailscale
// API, separate from what it asked for. "Approved" means the attribute was
// written; "confirmed" means it was read back.
type Enforcement struct {
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"` // attribute read back present after approval
	RemovedAt   *time.Time `json:"removed_at,omitempty"`   // attribute read back absent after expiry or revoke
	CheckedAt   *time.Time `json:"checked_at,omitempty"`   // last check
	Error       string     `json:"error,omitempty"`        // last check failed
}

// Event is one entry in an access request's timeline.
type Event struct {
	Type      string    `json:"type"` // submitted approval approved approve_failed declined cancelled revoked revoke_failed expired
	Actor     string    `json:"actor"`
	Note      string    `json:"note,omitempty"`
	Via       string    `json:"via,omitempty"`        // "slack" when the actor acted through Slack
	SlackUser string    `json:"slack_user,omitempty"` // with Via "slack": "<team>/<user>"
	At        time.Time `json:"at"`
}

// Event types a Notifier sees that are not timeline entries: the device
// attribute was read back present, or gone.
const (
	EventConfirmed = "confirmed"
	EventRemoved   = "removed"
)

// AccessRequest is a request for time-limited access through one workflow.
type AccessRequest struct {
	ID           string `json:"id"`
	URL          string `json:"url,omitempty"` // approval page; set by the HTTP layer, not stored
	WorkflowID   string `json:"workflow_id"`
	WorkflowName string `json:"workflow_name"`
	// Attribute and Resources are snapshots of the workflow at submit, so a
	// request stays readable after its flow changes.
	Attribute      string      `json:"attribute"`
	OktaGroups     []OktaGroup `json:"okta_groups,omitempty"`
	Resources      []Resource  `json:"resources"`
	Requester      Identity    `json:"requester"`
	TargetDeviceID string      `json:"target_device_id"`
	Duration       Duration    `json:"duration"`
	Reason         string      `json:"reason"`
	Status         Status      `json:"status"`
	Timeline       []Event     `json:"timeline"`
	// Approvals so far; access is granted once ApprovalsRequired is reached.
	Approvals         []Approval  `json:"approvals,omitempty"`
	ApprovalsRequired int         `json:"approvals_required"` // the flow's quorum; follows the flow while pending
	Enforcement       Enforcement `json:"enforcement"`
	ApprovedAt        *time.Time  `json:"approved_at,omitempty"`
	ExpiresAt         *time.Time  `json:"expires_at,omitempty"`
	Attributes        []string    `json:"attributes,omitempty"` // [Attribute] once it was set on approve; empty if never granted
	LastError         string      `json:"last_error,omitempty"`
	// Okta is what approval did in Okta, for flows with OktaGroups.
	Okta *OktaGrant `json:"okta,omitempty"`
	// Slack lists the Slack messages posted about this request.
	Slack     []SlackMessage `json:"slack,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	// Policy is what the tailnet policy grants for Attribute; set by the
	// HTTP layer, not stored.
	Policy *PolicyUse `json:"policy,omitempty"`
	// ApprovalsCounted is how many of Approvals still count under the flow
	// as it is now (see Service.CountVotes); worked out when read.
	ApprovalsCounted int `json:"approvals_counted"`
}

// ResourceNames lists the request's resource names.
func (r *AccessRequest) ResourceNames() []string { return resourceNames(r.Resources) }

// OktaGroupLabels lists the request's Okta group names.
func (r *AccessRequest) OktaGroupLabels() []string { return oktaLabels(r.OktaGroups) }

// Granted reports whether access was ever put in place for r: the posture
// attribute set, or Okta memberships handled.
func (r *AccessRequest) Granted() bool {
	return len(r.Attributes) > 0 || (r.Okta != nil && r.Okta.UserID != "")
}

// oktaPendingRemoval reports whether r ended with Okta memberships jitd
// added that are not yet confirmed removed.
func (r *AccessRequest) oktaPendingRemoval() bool {
	ended := r.Status == StatusExpired || r.Status == StatusRevoked
	return ended && r.Okta != nil && len(r.Okta.Added) > 0 && r.Okta.RemovedAt == nil
}

var attrNameRE = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// AttrKey turns an attribute name ("db_ro") or a full key into the full
// key custom:jit_db_ro.
func AttrKey(name string) string {
	return AttrPrefix + strings.TrimPrefix(strings.TrimSpace(strings.ToLower(name)), AttrPrefix)
}

// IsLogin reports whether p names one user by login (not a group, tag or
// autogroup).
func (p Principal) IsLogin() bool {
	s := string(p)
	return strings.Contains(s, "@") && !strings.HasPrefix(s, "group:") && !strings.HasPrefix(s, "tag:") && !strings.HasPrefix(s, "autogroup:") && !strings.HasPrefix(s, OktaPrefix)
}

// ValidatePrincipal checks principal syntax.
func ValidatePrincipal(p Principal) error {
	s := string(p)
	switch {
	case p == AutogroupMember:
	case strings.HasPrefix(s, "tag:") && len(s) > 4:
	case strings.HasPrefix(s, "group:") && len(s) > 6:
	case strings.HasPrefix(s, OktaPrefix) && strings.TrimSpace(s[len(OktaPrefix):]) != "" && !strings.ContainsAny(s, ",\"\n\t"):
	case strings.Count(s, "@") == 1 && !strings.ContainsAny(s, " ,"):
	default:
		return fmt.Errorf("invalid principal %q: use a login email, tag:<name>, group:<name>, okta:<Okta group>, or autogroup:member", s)
	}
	return nil
}

// Normalize trims and de-duplicates fields and applies defaults.
func (w *Workflow) Normalize() {
	w.Name = strings.TrimSpace(w.Name)
	w.Description = strings.TrimSpace(w.Description)
	if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(w.Attribute), AttrPrefix)) == "" {
		w.Attribute = ""
	} else {
		w.Attribute = AttrKey(w.Attribute)
	}
	w.OktaGroups = cleanOktaGroups(w.OktaGroups)
	w.Resources = cleanResources(w.Resources)
	w.Requesters = cleanPrincipals(w.Requesters)
	w.Approvers = cleanPrincipals(w.Approvers)
	if w.MaxDuration == 0 {
		w.MaxDuration = DefaultMaxDuration
	}
	if w.ApprovalTimeout == 0 {
		w.ApprovalTimeout = DefaultApprovalTimeout
	}
	if w.ApprovalsRequired == 0 {
		w.ApprovalsRequired = 1
	}
	if w.DefaultDuration == 0 {
		w.DefaultDuration = min(DefaultMaxDuration, w.MaxDuration)
	}
	if w.Slack != nil {
		w.Slack.Channel = strings.TrimSpace(w.Slack.Channel)
		w.Slack.ChannelName = strings.TrimPrefix(strings.TrimSpace(w.Slack.ChannelName), "#")
		if w.Slack.Channel == "" {
			w.Slack.ChannelName = ""
		}
		if *w.Slack == (WorkflowSlack{}) {
			w.Slack = nil
		}
	}
}

// slackChannelRE is the shape of a Slack conversation ID.
var slackChannelRE = regexp.MustCompile(`^[CG][A-Z0-9]{6,}$`)

// Validate checks a normalized workflow.
func (w *Workflow) Validate() error {
	if w.Name == "" {
		return badRequest("name is required")
	}
	if w.Attribute == "" && len(w.OktaGroups) == 0 {
		return badRequest("an approval flow must grant something: a posture attribute, Okta groups, or both")
	}
	if w.Attribute != "" {
		name := strings.TrimPrefix(w.Attribute, AttrPrefix)
		if !attrNameRE.MatchString(name) {
			return badRequest("invalid posture attribute %q: use 1-32 of a-z, 0-9, _ after %s (e.g. db_ro, ssh)", name, AttrPrefix)
		}
		if name == ReservedAttribute {
			return badRequest("the posture attribute %s%s is reserved for jitd's setup check", AttrPrefix, name)
		}
	}
	if len(w.OktaGroups) > MaxOktaGroups {
		return badRequest("an approval flow may grant at most %d Okta groups", MaxOktaGroups)
	}
	for _, g := range w.OktaGroups {
		if g.ID == "" {
			return badRequest("Okta group %q has not been looked up; is Okta configured?", g.Name)
		}
	}
	for _, r := range w.Resources {
		if strings.ContainsAny(r.Name, " \t,\"") {
			return badRequest("invalid target %q: one name without spaces or commas (svc:..., tag:..., a host or a CIDR); add a row per target", r.Name)
		}
		if len(r.Description) > MaxResourceDescription {
			return badRequest("description of %s is longer than %d characters", r.Name, MaxResourceDescription)
		}
	}
	if len(w.Requesters) == 0 {
		return badRequest("at least one requester is required")
	}
	if len(w.Approvers) == 0 {
		return badRequest("at least one approver is required")
	}
	for _, p := range append(append([]Principal{}, w.Requesters...), w.Approvers...) {
		if err := ValidatePrincipal(p); err != nil {
			return badRequest("%v", err)
		}
	}
	if w.MaxDuration < Duration(time.Minute) {
		return badRequest("the maximum duration must be at least 1 minute")
	}
	if w.ApprovalTimeout < Duration(time.Minute) {
		return badRequest("the approval timeout must be at least 1 minute")
	}
	if w.ApprovalsRequired < 1 || w.ApprovalsRequired > MaxApprovalsRequired {
		return badRequest("approvals required must be between 1 and %d", MaxApprovalsRequired)
	}
	if w.DefaultDuration < Duration(time.Minute) {
		return badRequest("the default duration must be at least 1 minute")
	}
	for _, d := range []struct {
		what string
		v    Duration
	}{{"maximum duration", w.MaxDuration}, {"default duration", w.DefaultDuration}, {"approval timeout", w.ApprovalTimeout}} {
		if d.v > MaxFlowDuration {
			return badRequest("the %s (%s) is longer than the limit of %s", d.what, d.v.Human(), MaxFlowDuration.Human())
		}
	}
	if w.DefaultDuration > w.MaxDuration {
		return badRequest("the default duration (%s) is longer than the maximum (%s)", w.DefaultDuration.Human(), w.MaxDuration.Human())
	}
	// With only named approvers, the quorum must be reachable at all.
	named := 0
	for _, p := range w.Approvers {
		if p.IsLogin() {
			named++
		}
	}
	if named == len(w.Approvers) && named < w.ApprovalsRequired {
		return badRequest("approvals_required is %d but only %d approvers are listed", w.ApprovalsRequired, named)
	}
	if w.Slack != nil && w.Slack.Channel != "" && !slackChannelRE.MatchString(w.Slack.Channel) {
		return badRequest("invalid Slack channel ID %q: pick a channel from the list", w.Slack.Channel)
	}
	return nil
}

// MaxOktaGroups caps how many Okta groups one flow grants.
const MaxOktaGroups = 20

// cleanOktaGroups trims, drops empties and de-duplicates by ID (or name, for
// groups not looked up yet). A name that is really a group ID moves to ID.
func cleanOktaGroups(in []OktaGroup) []OktaGroup {
	var out []OktaGroup
	seen := map[string]bool{}
	for _, g := range in {
		g.ID, g.Name = strings.TrimSpace(g.ID), strings.TrimSpace(g.Name)
		if g.ID == "" && oktaGroupIDRE.MatchString(g.Name) {
			g.ID, g.Name = g.Name, ""
		}
		k := "id:" + g.ID
		if g.ID == "" {
			k = "name:" + g.Name
		}
		if (g.ID != "" || g.Name != "") && !seen[k] {
			seen[k] = true
			out = append(out, g)
		}
	}
	return out
}

// oktaGroupIDRE is the shape of an Okta group ID (00g…).
var oktaGroupIDRE = regexp.MustCompile(`^00g[A-Za-z0-9]{10,}$`)

// MaxResourceDescription caps a resource description.
const MaxResourceDescription = 200

// cleanResources trims, drops empties and keeps the first of duplicate names.
func cleanResources(in []Resource) []Resource {
	var out []Resource
	seen := map[string]bool{}
	for _, r := range in {
		r.Name = strings.TrimSpace(r.Name)
		r.Description = strings.TrimSpace(r.Description)
		if r.Name != "" && !seen[r.Name] {
			seen[r.Name] = true
			out = append(out, r)
		}
	}
	return out
}

func cleanPrincipals(in []Principal) []Principal {
	var out []Principal
	seen := map[string]bool{}
	for _, p := range in {
		p = Principal(strings.TrimSpace(string(p)))
		// Logins match case-insensitively everywhere else, so Alice@ and
		// alice@ are one approver here too.
		if k := strings.ToLower(string(p)); p != "" && !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

// NewID returns prefix + 16 random hex characters.
func NewID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
