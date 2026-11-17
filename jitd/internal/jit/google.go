package jit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
)

// Google as a group provider (see groups.go for what jitd does with one).
//
// A Google group has members by email address, so the requester's login is
// the member: there is no user to look up, and nothing tells jitd whether
// the address is a person in this organisation. GoogleLimits.Domains is
// what stands in for that.

// GoogleLimits is what jitd may do with Google groups.
type GoogleLimits struct {
	// Grant lists the groups approval flows may grant, by address or ID,
	// with * as a wildcard. Nil allows every group, an empty list none.
	Grant []string
	// Domains are the email domains whose logins jitd may add to a group
	// (lower case). With none, nobody is added: a login from somewhere
	// else would otherwise become an outside member wherever a group
	// allows those.
	Domains []string
}

// NoGoogleGroups allows nothing, for when the settings cannot be read.
func NoGoogleGroups() GoogleLimits { return GoogleLimits{Grant: []string{}} }

// ParseGoogleLimits reads the limits from jitd's Google settings (see
// google.EnvGrantAllowlist and google.EnvDomains). A grant allowlist that
// is absent allows every group; one that is present and empty allows none.
func ParseGoogleLimits(vars map[string]string) GoogleLimits {
	lim := GoogleLimits{Grant: listOf(vars, google.EnvGrantAllowlist)}
	for i, g := range lim.Grant {
		lim.Grant[i] = strings.ToLower(g) // addresses are stored in lower case
	}
	for _, d := range splitList(vars[google.EnvDomains]) {
		d = strings.ToLower(strings.TrimPrefix(d, "@"))
		if !slices.Contains(lim.Domains, d) {
			lim.Domains = append(lim.Domains, d)
		}
	}
	return lim
}

func (s *Service) googleLimits() GoogleLimits {
	if s.GoogleLimits == nil {
		return NoGoogleGroups()
	}
	return s.GoogleLimits()
}

// googleEnabled reports whether jitd may use Google for something new: a
// grant, a flow that names Google groups. Like oktaEnabled, it does not
// gate looking after what jitd already did.
func (s *Service) googleEnabled() bool {
	if s.Google == nil {
		return false
	}
	if e, ok := s.Google.(interface{ Enabled() bool }); ok {
		return e.Enabled()
	}
	return true
}

// GoogleEnabled reports whether Google group grants are available.
func (s *Service) GoogleEnabled() bool { return s.googleEnabled() }

func (s *Service) googleWhyOff() string {
	if e, ok := s.Google.(interface{ Err() error }); ok {
		if err := e.Err(); err != nil && !errors.Is(err, google.ErrUnconfigured) {
			return err.Error()
		}
	}
	return "Google is not configured"
}

func (s *Service) googleStale() string {
	if st, ok := s.Google.(interface{ StaleSettings() string }); ok {
		return st.StaleSettings()
	}
	return ""
}

// googleProvider is Google as this jitd has it now.
func (s *Service) googleProvider() *groupProvider {
	p := &groupProvider{
		groupKind: googleKind,
		on:        s.googleEnabled,
		whyOff:    s.googleWhyOff,
		stale:     s.googleStale,
		allow:     func() GroupAllowlist { return GroupAllowlist{Grant: s.googleLimits().Grant} },
		grantEnv:  "set on jitd's Google page",
		setup:     "an admin can set it up on jitd's Google page",
		health:    &s.ggHealth,
	}
	if s.Google != nil {
		p.client = googleGroups{c: s.Google, domains: func() []string { return s.googleLimits().Domains }}
	}
	return p
}

// googleGroups is a Google client as a groupClient.
type googleGroups struct {
	c       google.Client
	domains func() []string
}

// Member is the login itself, as an address: Google has members by email.
// It is refused unless its domain is one jitd may add.
func (g googleGroups) Member(_ context.Context, login string) (id, label string, err error) {
	email := strings.ToLower(strings.TrimSpace(login))
	_, domain, ok := strings.Cut(email, "@")
	if !ok || domain == "" {
		return "", "", fmt.Errorf("%q is not an email address, so it cannot be a member of a Google group", login)
	}
	if !slices.Contains(g.domains(), domain) {
		return "", "", fmt.Errorf("jitd may not add %s to Google groups: %s is not one of the allowed domains on jitd's Google page", email, domain)
	}
	return email, email, nil
}

// noGoogleGroup is what to say when Google shows no such group.
func noGoogleGroup(ref string) string {
	s := fmt.Sprintf("Google has no group %q that jitd's service account can see.", ref)
	if !strings.Contains(ref, "@") {
		s += " Name the group by its email address."
	}
	return s + " If the group exists, the Groups Admin role is not assigned to the service account yet (a new assignment can take a few minutes)."
}

func (g googleGroups) Group(ctx context.Context, ref string) (GroupRef, error) {
	grp, err := g.c.FindGroup(ctx, ref)
	if errors.Is(err, google.ErrNotFound) {
		return GroupRef{}, badRequest("%s", noGoogleGroup(ref))
	}
	if err != nil {
		return GroupRef{}, err
	}
	if !grp.Manageable() {
		return GroupRef{}, badRequest("Google group %q is a dynamic group: its members come from a query, so Google does not let jitd change them", googleLabel(grp))
	}
	return GroupRef{ID: grp.ID, Name: googleLabel(grp)}, nil
}

// googleLabel is the group's address, which is how people know it.
func googleLabel(g google.Group) string {
	if g.Email != "" {
		return strings.ToLower(g.Email)
	}
	if g.Name != "" {
		return g.Name
	}
	return g.ID
}

func (g googleGroups) IsMember(ctx context.Context, groupID, memberID string) (bool, error) {
	return g.c.IsMember(ctx, groupID, memberID)
}

func (g googleGroups) Add(ctx context.Context, groupID, memberID string) error {
	return g.c.AddMember(ctx, groupID, memberID)
}

func (g googleGroups) Remove(ctx context.Context, groupID, memberID string) error {
	return g.c.RemoveMember(ctx, groupID, memberID)
}

// Holding asks Google about each group: with jitd's scope there is no call
// that lists one member's groups.
func (g googleGroups) Holding(ctx context.Context, memberID string, groupIDs []string) (map[string]bool, error) {
	in := map[string]bool{}
	for _, id := range groupIDs {
		ok, err := g.c.IsMember(ctx, id, memberID)
		if err != nil {
			return in, err
		}
		in[id] = ok
	}
	return in, nil
}

func (g googleGroups) Check(ctx context.Context) error { return g.c.Check(ctx) }

func (g googleGroups) Refused(err error) bool { return google.IsRefusal(err) }

// GoogleState reports how jitd's use of Google stands, for the Google page.
func (s *Service) GoogleState() GroupState { return s.groupState(s.googleProvider()) }

// GoogleCheckNow tries the Google credentials now rather than at the next
// check that is due, and returns what Google said.
func (s *Service) GoogleCheckNow(ctx context.Context) error {
	return s.groupCheckNow(ctx, s.googleProvider())
}

// GoogleProblems lists what an admin should know about Google right now
// (see OktaProblems). Empty when all is well.
func (s *Service) GoogleProblems() []GroupProblem { return s.groupProblems(s.googleProvider()) }

// GoogleGroupCheck is what jitd can tell about one Google group without
// changing anything in Google.
type GoogleGroupCheck struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	// Manageable: Google lets an API client change the members (not a
	// dynamic group, whose members come from a query).
	Manageable bool `json:"manageable"`
	// GrantAllowed: the allowlist lets a flow grant it.
	GrantAllowed bool `json:"grant_allowed"`
}

// CheckGoogleGroup looks one group up, by address or ID, with jitd's
// credential. It only reads. That jitd may add and remove members shows the
// first time a request is approved.
func (s *Service) CheckGoogleGroup(ctx context.Context, ref string) (GoogleGroupCheck, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return GoogleGroupCheck{}, badRequest("name a Google group, by its email address")
	}
	if !s.googleEnabled() {
		return GoogleGroupCheck{}, conflict("%s", s.googleWhyOff())
	}
	actx, cancel := apiContext(ctx)
	defer cancel()
	g, err := s.Google.FindGroup(actx, ref)
	if errors.Is(err, google.ErrNotFound) {
		return GoogleGroupCheck{}, notFound("%s", noGoogleGroup(ref))
	}
	if err != nil {
		return GoogleGroupCheck{}, apiFailed("looking up Google group %q: %v", ref, err)
	}
	p := s.googleProvider()
	return GoogleGroupCheck{
		ID: g.ID, Email: strings.ToLower(g.Email), Name: g.Name, Manageable: g.Manageable(),
		GrantAllowed: p.grantAllowed(GroupRef{ID: g.ID, Name: googleLabel(g)}),
	}, nil
}
