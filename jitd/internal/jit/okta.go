package jit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// Okta as a group provider (see groups.go for what jitd does with one).

// oktaEnabled reports whether jitd may use Okta for something new: a grant,
// a flow that names Okta groups, an okta: principal. It is false without
// usable credentials (and it is where a switch to turn Okta off belongs).
//
// It must not gate looking after what jitd already did. Taking memberships
// back, retrying, and telling the admins run whenever there is an Okta
// client at all (see groupUpkeep): if Okta is off while memberships are in
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

// oktaWhyOff says why Okta is off, for people.
func (s *Service) oktaWhyOff() string {
	if e, ok := s.Okta.(interface{ Err() error }); ok {
		if err := e.Err(); err != nil {
			return err.Error()
		}
	}
	return "Okta is not configured"
}

// oktaStale says why jitd could not re-read its Okta settings, if it could
// not.
func (s *Service) oktaStale() string {
	if st, ok := s.Okta.(interface{ StaleSettings() string }); ok {
		return st.StaleSettings()
	}
	return ""
}

// oktaProvider is Okta as this jitd has it now.
func (s *Service) oktaProvider() *groupProvider {
	p := &groupProvider{
		groupKind: oktaKind,
		on:        s.oktaEnabled,
		whyOff:    s.oktaWhyOff,
		stale:     s.oktaStale,
		allow:     s.oktaAllow,
		grantEnv:  EnvOktaGrantAllowlist,
		setup:     "an admin can set it up on jitd's Okta page (or set OKTA_ORG_URL and either OKTA_API_TOKEN or OKTA_CLIENT_ID and OKTA_PRIVATE_KEY in jitd's env file)",
		health:    &s.okHealth,
	}
	if s.Okta != nil {
		p.client = oktaGroups{s.Okta}
	}
	return p
}

// oktaGroups is an Okta client as a groupClient.
type oktaGroups struct{ c okta.Client }

func (o oktaGroups) Member(ctx context.Context, login string) (id, label string, err error) {
	u, err := o.c.FindUser(ctx, login)
	if err != nil {
		return "", "", fmt.Errorf("finding the Okta user for %s: %w", login, err)
	}
	if !u.Active() {
		return "", "", fmt.Errorf("the Okta user %s is %s, not active", u.Profile.Login, strings.ToLower(u.Status))
	}
	return u.ID, u.Profile.Login, nil
}

func (o oktaGroups) Group(ctx context.Context, ref string) (GroupRef, error) {
	g, err := o.c.FindGroup(ctx, ref)
	if errors.Is(err, okta.ErrNotFound) {
		return GroupRef{}, errNoGroup
	}
	if err != nil {
		return GroupRef{}, err
	}
	if !g.Manageable() {
		return GroupRef{}, badRequest("Okta group %q is a %s group: its members come from a directory or app, so Okta does not let jitd change them", g.Name(), g.Type)
	}
	return GroupRef{ID: g.ID, Name: g.Name()}, nil
}

func (o oktaGroups) IsMember(ctx context.Context, groupID, memberID string) (bool, error) {
	return o.c.IsMember(ctx, groupID, memberID)
}

func (o oktaGroups) Add(ctx context.Context, groupID, memberID string) error {
	return o.c.AddMember(ctx, groupID, memberID)
}

func (o oktaGroups) Remove(ctx context.Context, groupID, memberID string) error {
	return o.c.RemoveMember(ctx, groupID, memberID)
}

// Holding asks Okta once for all of the user's groups.
func (o oktaGroups) Holding(ctx context.Context, memberID string, _ []string) (map[string]bool, error) {
	gs, err := o.c.UserGroups(ctx, memberID)
	in := map[string]bool{}
	for _, g := range gs {
		in[g.ID] = true
	}
	return in, err
}

func (o oktaGroups) Check(ctx context.Context) error { return o.c.Check(ctx) }

func (o oktaGroups) Refused(err error) bool { return okta.IsRefusal(err) }

// OktaState is how jitd's use of Okta stands, for the Okta page.
type OktaState = GroupState

// OktaState reports how jitd's use of Okta stands.
func (s *Service) OktaState() OktaState { return s.groupState(s.oktaProvider()) }

// OktaCheckNow tries the Okta credentials now rather than at the next
// check that is due, and returns what Okta said. An admin asks for this on
// the Okta page, and saving credentials there does it.
func (s *Service) OktaCheckNow(ctx context.Context) error {
	return s.groupCheckNow(ctx, s.oktaProvider())
}

// OktaProblem is something about Okta an admin should look at.
type OktaProblem = GroupProblem

// OktaProblems lists what an admin should know about Okta right now: Okta
// is off while memberships jitd added are still in place, the env file
// cannot be read, the credentials do not work, a removal is stuck, or an
// unfinished approval could not be taken back. Empty when all is well.
func (s *Service) OktaProblems() []OktaProblem { return s.groupProblems(s.oktaProvider()) }
