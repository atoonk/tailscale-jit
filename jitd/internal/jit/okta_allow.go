package jit

import (
	"slices"
	"strings"
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
// ("jit.*", "Team-*"). A list that is not set defaults to "*":
// every group.

// OktaAllowlist holds the two lists.
type OktaAllowlist struct {
	Grant []string
	Read  []string
}

// Env variables holding the lists, comma-separated.
const (
	EnvOktaGrantAllowlist = "OKTA_GRANT_ALLOWLIST"
	EnvOktaReadAllowlist  = "OKTA_READ_ALLOWLIST"
)

// DefaultOktaAllowlist is what a list that is not set means: every group.
const DefaultOktaAllowlist = "*"

// ParseOktaAllowlist reads the lists from env-style variables. A list that
// is not set (or has no entries) is DefaultOktaAllowlist.
func ParseOktaAllowlist(vars map[string]string) OktaAllowlist {
	return OktaAllowlist{Grant: listOrDefault(vars[EnvOktaGrantAllowlist]), Read: listOrDefault(vars[EnvOktaReadAllowlist])}
}

func listOrDefault(s string) []string {
	if l := splitList(s); len(l) > 0 {
		return l
	}
	return []string{DefaultOktaAllowlist}
}

// AllowsAll reports whether list lets every group through.
func AllowsAll(list []string) bool { return len(list) == 0 || slices.Contains(list, "*") }

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// allowed reports whether a group, by ID or name, is on list. An empty list
// allows everything.
func allowed(list []string, id, name string) bool {
	if len(list) == 0 {
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
