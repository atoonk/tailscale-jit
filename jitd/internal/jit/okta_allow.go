package jit

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// Okta group allowlists.
//
// They limit which Okta groups jitd will use, on top of whatever the Okta
// credential itself can do:
//
//   - Grant: groups a flow may add members to. Checked when a flow is saved
//     and again just before each approval adds anyone, so narrowing the list
//     stops grants through flows saved earlier. Removal is never blocked:
//     jitd can always take back access it gave.
//   - Read: groups an okta: principal may name. Checked when a flow is saved
//     and on every match; a group outside the list matches nobody.
//
// Each entry is a group name or ID; "*" matches any run of characters
// ("jit.*", "Team-*"). A list that is not set defaults to "*": every group.
// A list that is set but has no entries allows no group, and so does an env
// file jitd has not been able to read since it started. If the file stops
// being readable later, the lists read last stay in force (see main): a
// mistake in the env file must not open every group.

// OktaAllowlist holds the two lists. A nil list is one that was never set
// and allows every group; an empty, non-nil list allows none.
type OktaAllowlist struct {
	Grant []string
	Read  []string
}

// NoOktaGroups is the allowlist that lets no group through, for when the
// lists cannot be read.
func NoOktaGroups() OktaAllowlist { return OktaAllowlist{Grant: []string{}, Read: []string{}} }

// Env variables holding the lists, comma-separated.
const (
	EnvOktaGrantAllowlist = "OKTA_GRANT_ALLOWLIST"
	EnvOktaReadAllowlist  = "OKTA_READ_ALLOWLIST"
)

// DefaultOktaAllowlist is what a list that is not set means: every group.
const DefaultOktaAllowlist = "*"

// ParseOktaAllowlist reads the lists from env-style variables. A variable
// that is absent from vars is DefaultOktaAllowlist; one that is present
// with no entries ("OKTA_GRANT_ALLOWLIST=") allows nothing.
func ParseOktaAllowlist(vars map[string]string) OktaAllowlist {
	return OktaAllowlist{Grant: listOf(vars, EnvOktaGrantAllowlist), Read: listOf(vars, EnvOktaReadAllowlist)}
}

func listOf(vars map[string]string, key string) []string {
	v, set := vars[key]
	if !set {
		return []string{DefaultOktaAllowlist}
	}
	if l := splitList(v); len(l) > 0 {
		return l
	}
	return []string{}
}

// AllowsAll reports whether list lets every group through.
func AllowsAll(list []string) bool { return list == nil || slices.Contains(list, "*") }

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// allowed reports whether a group, by ID or name, is on list. A nil list
// (never set) allows everything; an empty one allows nothing.
func allowed(list []string, id, name string) bool {
	if list == nil {
		return true
	}
	for _, pat := range list {
		if (id != "" && globMatch(pat, id)) || (name != "" && globMatch(pat, name)) {
			return true
		}
	}
	return false
}

// globMatch matches s against pat, where "*" is any run of characters
// (including "/" and spaces, which Okta group names may contain) and
// everything else is literal.
func globMatch(pat, s string) bool {
	parts := strings.Split(pat, "*")
	if len(parts) == 1 {
		return pat == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// oktaAllow returns the current lists (re-read on each call, like the
// credentials, so editing the env file needs no restart).
func (s *Service) oktaAllow() OktaAllowlist {
	if s.OktaLimits == nil {
		return OktaAllowlist{}
	}
	return s.OktaLimits()
}

func (s *Service) grantAllowed(g OktaGroup) bool {
	return allowed(s.oktaAllow().Grant, g.ID, g.Name)
}

func (s *Service) readAllowed(id, name string) bool {
	return allowed(s.oktaAllow().Read, id, name)
}

// OktaGroupCheck is what jitd can tell about one Okta group without
// changing anything in Okta: whether a flow could grant it, and whether it
// could be used as an okta: principal.
type OktaGroupCheck struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	// Manageable: Okta lets an API client change the members (not a group
	// whose members come from a directory, an app or a rule).
	Manageable bool `json:"manageable"`
	// GrantAllowed and ReadAllowed: the allowlists let jitd grant it, and
	// read its members for an okta: principal.
	GrantAllowed bool `json:"grant_allowed"`
	ReadAllowed  bool `json:"read_allowed"`
	// Members is how many members jitd's credential can list (MembersCapped:
	// at least that many), or MembersError says why it cannot.
	Members       int    `json:"members"`
	MembersCapped bool   `json:"members_capped,omitempty"`
	MembersError  string `json:"members_error,omitempty"`
}

// CheckOktaGroup looks one group up, by name or ID, with jitd's credential.
// It only reads. That jitd may add and remove members shows the first time
// a request is approved: Okta has no way to ask without doing it.
func (s *Service) CheckOktaGroup(ctx context.Context, ref string) (OktaGroupCheck, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return OktaGroupCheck{}, badRequest("name an Okta group, by its name or its ID (00g…)")
	}
	if !s.oktaEnabled() {
		return OktaGroupCheck{}, conflict("%s", s.oktaWhyOff())
	}
	actx, cancel := apiContext(ctx)
	defer cancel()
	g, err := s.Okta.FindGroup(actx, ref)
	if errors.Is(err, okta.ErrNotFound) {
		return OktaGroupCheck{}, notFound("Okta has no group %q that jitd's credential can see. If the group exists, the credential's admin role does not cover it.", ref)
	}
	if err != nil {
		return OktaGroupCheck{}, apiFailed("looking up Okta group %q: %v", ref, err)
	}
	out := OktaGroupCheck{
		ID: g.ID, Name: g.Name(), Type: g.Type, Manageable: g.Manageable(),
		GrantAllowed: s.grantAllowed(OktaGroup{ID: g.ID, Name: g.Name()}),
		ReadAllowed:  s.readAllowed(g.ID, g.Name()),
	}
	us, err := s.Okta.GroupMembers(actx, g.ID)
	if err != nil {
		out.MembersError = err.Error()
	} else {
		out.Members, out.MembersCapped = len(us), len(us) >= okta.MaxGroupMembers
	}
	return out, nil
}
