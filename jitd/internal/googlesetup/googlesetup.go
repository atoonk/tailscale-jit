// Package googlesetup looks after jitd's Google settings: the service
// account key (from the environment, the env file, or the Google page,
// which keeps it in jitd's database), which groups flows may grant and
// whose logins may be added, and trying, saving and removing what is set
// on the page.
package googlesetup

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

// settingKey is where what the page saved lives in the store.
const settingKey = "google"

// checkTimeout bounds trying a key against Google before saving it.
const checkTimeout = 30 * time.Second

// Manager decides which Google settings are in force, and changes the ones
// saved on the Google page.
//
// The page is where these are set. A value in the environment or the env
// file still wins, one by one: whoever runs the box (or the Kubernetes
// Secret) has the last word, and the page then shows that value and does
// not change it.
type Manager struct {
	Store *jit.Store
	Svc   *jit.Service
	// Env returns the Google variables set outside the database: the key
	// if it is not empty there, and the two lists if they are named there
	// at all. Nil means none.
	Env func() (map[string]string, error)
	// EnvFile is the env file's path, for the page to name. It may be empty.
	EnvFile string
	// Dial builds a client to try a key with. It is google.NewFromValues
	// unless set (the preview and tests use a fake).
	Dial func(vars map[string]string) (google.Client, error)
	Log  *slog.Logger
	Now  func() time.Time

	once    sync.Once
	mu      sync.Mutex
	saved   *google.Settings // what the page saved; nil when nothing
	loadErr error
}

// Input is what the Google page's form sends.
type Input struct {
	// Key is the service account's JSON key file, whole. Empty keeps the
	// key jitd already has and saves the rest.
	Key string `json:"key"`
	// Domains are the email domains whose users jitd may add to groups,
	// separated by commas or spaces.
	Domains string `json:"allowed_domains"`
	// Grant lists the groups flows may grant, by address, with * as
	// a wildcard, separated by commas or spaces.
	Grant string `json:"grant_allowlist"`
	// Force saves a key for another service account although jitd still
	// has memberships to look after (see Save). From ?force=1, not from
	// the body.
	Force bool `json:"-"`
}

// Sources of the key in force.
const (
	SourceUI  = "ui"  // saved on the Google page
	SourceEnv = "env" // the environment or the env file
)

// Status is the Google connection as the page and GET /v1/google show it.
// It never carries the key.
type Status struct {
	Source  string `json:"source"` // SourceUI, SourceEnv, or "" when there is no key
	EnvFile string `json:"env_file,omitempty"`
	// Shadowed: a key saved on the page is being ignored, because the
	// environment or the env file sets its own.
	Shadowed bool `json:"shadowed,omitempty"`
	// Enabled: there is a key and it is well-formed. Whether Google
	// accepts it is Error.
	Enabled bool `json:"enabled"`
	// The service account the key is for, and where its API is enabled.
	Account   string    `json:"service_account,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	Project   string    `json:"project,omitempty"`
	EnableURL string    `json:"enable_url,omitempty"`
	SavedBy   string    `json:"saved_by,omitempty"`
	SavedAt   time.Time `json:"saved_at,omitzero"`
	// CheckedAt is when jitd last tried the key against Google. Error and
	// Fix say what is wrong, if anything, and what to do.
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Error     string    `json:"error,omitempty"`
	Fix       string    `json:"fix,omitempty"`
	// RoleSeen: that check found a group jitd's flows use, which takes the
	// Groups Admin role. False also when there was no group to look for:
	// Google's answer to the key alone is the same with or without the
	// role.
	RoleSeen bool `json:"role_seen"`
	// The limits in force: whose logins may be added (none: nobody), and
	// which groups flows may grant ("*" is every group; empty is none).
	// The FromEnv flags say that the value comes from the environment or
	// the env file, so the page cannot change it.
	Domains        []string `json:"allowed_domains"`
	DomainsFromEnv bool     `json:"allowed_domains_from_env,omitempty"`
	GrantAllowlist []string `json:"grant_allowlist"`
	GrantFromEnv   bool     `json:"grant_allowlist_from_env,omitempty"`
	// Held counts the requests whose Google memberships jitd still has to
	// look after. It cannot remove them while Google is off.
	Held int `json:"held"`
}

// Configured reports whether there is a service account key at all.
func (st Status) Configured() bool { return st.Source != "" }

// Working reports whether the key was tried and Google took it. That the
// service account can manage groups is RoleSeen.
func (st Status) Working() bool { return st.Enabled && st.Error == "" && !st.CheckedAt.IsZero() }

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// Load reads what the page saved from the store. Call it at startup: later
// calls for the settings (Vars runs under the service's and the store's
// locks) must find them in memory and not go back to the store.
func (m *Manager) Load() error {
	_, err := m.load()
	return err
}

// load returns what the page saved, reading the store the first time only.
func (m *Manager) load() (*google.Settings, error) {
	m.once.Do(func() {
		var s google.Settings
		found, err := m.Store.GetSetting(settingKey, &s)
		m.mu.Lock()
		defer m.mu.Unlock()
		if err != nil {
			m.loadErr = err
		} else if found {
			m.saved = &s
		}
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saved, m.loadErr
}

func (m *Manager) env() (map[string]string, error) {
	if m.Env == nil {
		return map[string]string{}, nil
	}
	return m.Env()
}

// Vars returns the Google variables in force, for google.Dynamic and
// jit.ParseGoogleLimits: what the page saved, with each value the
// environment or the env file sets in its place.
func (m *Manager) Vars() (map[string]string, error) {
	env, err := m.env()
	if err != nil {
		return nil, err
	}
	saved, err := m.load()
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	if saved != nil {
		vars = saved.Vars()
	}
	for k, v := range env {
		if k == google.EnvKey && strings.TrimSpace(v) == "" {
			continue
		}
		vars[k] = v
	}
	return vars, nil
}

// Status describes the connection.
func (m *Manager) Status() Status {
	st := Status{EnvFile: m.EnvFile, Domains: []string{}, GrantAllowlist: []string{}}
	state := m.Svc.GoogleState()
	st.Enabled, st.Held = state.Enabled, state.Held
	if m.Svc.GoogleLimits != nil {
		lim := m.Svc.GoogleLimits()
		st.GrantAllowlist = shown(lim.Grant)
		st.Domains = append(st.Domains, lim.Domains...)
	}
	// Without a key there is no project to name: the link then opens the
	// API in whichever project the console has selected.
	st.EnableURL = google.EnableURL("")
	env, err := m.env()
	if err != nil {
		// The env file cannot be read, so jitd cannot tell what it sets.
		st.Source = SourceEnv
		st.Error = "jitd cannot read its Google settings: " + err.Error()
		st.Fix = "Fix the env file. Until then jitd carries on with the settings it read last, if it has read any since it started."
		return st
	}
	_, st.DomainsFromEnv = env[google.EnvDomains]
	_, st.GrantFromEnv = env[google.EnvGrantAllowlist]
	saved, err := m.load()
	if err != nil {
		st.Error = "jitd cannot read the Google settings saved here from its database: " + err.Error()
		return st
	}
	text := ""
	switch {
	case google.Configured(env):
		st.Source, text = SourceEnv, env[google.EnvKey]
		st.Shadowed = saved != nil && saved.Key != ""
	case saved != nil && saved.Key != "":
		st.Source, text = SourceUI, saved.Key
		st.SavedBy, st.SavedAt = saved.SavedBy, saved.SavedAt
	default:
		return st
	}
	key, _ := google.ParseKey(text)
	if key != nil {
		st.Account, st.KeyID, st.Project = key.Email, key.ID, key.Project
		st.EnableURL = google.EnableURL(key.Project)
	}
	switch {
	case !state.Enabled:
		st.Error = "This key cannot be used: " + state.Off
		if st.Source == SourceEnv {
			st.Fix = "Fix it where it is set; jitd reads it again on its own."
		} else {
			st.Fix = "Replace it below."
		}
	case state.Err != nil:
		st.Error, st.Fix = google.Explain(state.Err, key)
	}
	if state.Enabled {
		st.CheckedAt = state.CheckedAt
	}
	st.RoleSeen = st.Working() && m.Svc.GoogleRoleSeen()
	return st
}

// Save stores what the page sent. A new key is tried against Google first
// and stored only if Google takes it; it is in force from the next Google
// call on. Without a key in the input, the key jitd has stays and only the
// limits change.
//
// jitd cannot tell which Workspace a service account manages. One for
// another Workspace does not see the groups jitd added people to, so it
// cannot take them out, and where Google answers that such a group does
// not exist jitd records the removal as done. So while jitd holds any
// membership, a key for another service account needs in.Force; a new key
// for the same account does not.
func (m *Manager) Save(ctx context.Context, admin jit.Identity, in Input) (Status, error) {
	env, err := m.env()
	if err != nil {
		return Status{}, &jit.Error{Code: "conflict", Status: http.StatusConflict,
			Message: "jitd cannot read its env file, so it cannot tell which Google settings are set there: " + err.Error()}
	}
	saved, err := m.load()
	if err != nil {
		return Status{}, err
	}
	s := google.Settings{Key: strings.TrimSpace(in.Key)}
	if s.Key != "" && google.Configured(env) {
		return Status{}, &jit.Error{Code: "conflict", Status: http.StatusConflict,
			Message: "The service account key is set in jitd's environment or env file (" + google.EnvKey + "); change it there. The domains and groups can still be saved here: leave the key out."}
	}
	_, domainsEnv := env[google.EnvDomains]
	_, grantEnv := env[google.EnvGrantAllowlist]
	if s.Domains, err = domains(in.Domains); err != nil {
		return Status{}, err
	}
	s.Grant = list(in.Grant)
	// Groups are matched by address, so a bare name matches none.
	for _, g := range s.Grant {
		if !grantEnv && !strings.ContainsAny(g, "@*") {
			like := s.Domains
			if len(like) == 0 && saved != nil {
				like = saved.Domains
			}
			return Status{}, bad(fmt.Sprintf("Nothing was saved: %q, in the groups a flow may grant, is not a group's email address, so it would match no group. Write the address, like %s, a pattern like aws-*@example.com, or * for every group.",
				g, jit.GoogleAddressLike(g, like)))
		}
	}
	// A list that is set in the environment, or left out here, stays as
	// it is saved.
	switch {
	case domainsEnv || len(s.Domains) == 0 && saved != nil && len(saved.Domains) > 0:
		s.Domains = nil
		if saved != nil {
			s.Domains = saved.Domains
		}
	case len(s.Domains) == 0:
		return Status{}, bad("Nothing was saved: fill in the email domains whose users jitd may add to groups, like example.com. Without one, jitd adds nobody.")
	}
	switch {
	case grantEnv || len(s.Grant) == 0 && saved != nil && len(saved.Grant) > 0:
		s.Grant = nil
		if saved != nil {
			s.Grant = saved.Grant
		}
	case len(s.Grant) == 0:
		return Status{}, bad("Nothing was saved: fill in which groups approval flows may grant: * for every group the service account can manage, or a list like aws-*@example.com.")
	}
	fresh := s.Key != ""
	cur := m.Status()
	other := false
	switch {
	case fresh:
		key, err := google.ParseKey(s.Key)
		if err != nil {
			return Status{}, bad("Nothing was saved: " + err.Error() + ".")
		}
		other = cur.Source == SourceUI && cur.Held > 0 && cur.Account != "" && !strings.EqualFold(cur.Account, key.Email)
		if other && !in.Force {
			return Status{}, &jit.Error{Code: "conflict", Status: http.StatusConflict, Force: true,
				Message: "Nothing was saved. jitd still has Google group memberships to look after, for " + plural(cur.Held, "request") + ", and it added them as " + cur.Account +
					". This key is for another service account, " + key.Email + ". If that one manages the same groups, nothing is lost. If it is for another Workspace, jitd cannot remove those memberships when the access ends, and may count them as removed while they stay in Google." +
					" End those requests first, or save anyway with force."}
		}
		dial := m.Dial
		if dial == nil {
			dial = func(vars map[string]string) (google.Client, error) { return google.NewFromValues(vars) }
		}
		c, err := dial(s.Vars())
		if err != nil {
			return Status{}, bad("Nothing was saved: " + err.Error() + ".")
		}
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		defer cancel()
		// This shows the key and the API, not the Groups Admin role:
		// Google gives no sign of that until a group is looked up.
		if err := c.Check(cctx); err != nil {
			what, fix := google.Explain(err, key)
			return Status{}, bad(strings.TrimSpace("Nothing was saved. " + what + " " + fix))
		}
	case saved != nil && saved.Key != "":
		s.Key = saved.Key
	case !google.Configured(env):
		return Status{}, bad("Nothing was saved: paste the service account's JSON key, the whole file.")
	}
	s.SavedBy, s.SavedAt = admin.Login, m.now().UTC()
	if err := m.Store.PutSetting(settingKey, s); err != nil {
		return Status{}, err
	}
	m.load() // so that a first save does not get overwritten by a late first read
	m.mu.Lock()
	m.saved, m.loadErr = &s, nil
	m.mu.Unlock()
	account := ""
	if key, _ := google.ParseKey(s.Key); key != nil {
		account = key.Email
	}
	if other {
		m.log().Warn("a key for another google service account saved while jitd holds memberships added with the old one", "was", cur.Account, "requests_still_held", cur.Held, "by", admin.Login)
	}
	m.log().Info("google settings saved on the Google page", "service_account", account, "new_key", fresh,
		"allowed_domains", s.Domains, "grant_allowlist", s.Grant, "by", admin.Login)
	m.Svc.GoogleCheckNow(ctx)
	return m.Status(), nil
}

// Remove forgets what the page saved, the key and the limits. Memberships
// jitd added stay its to remove, and it cannot until Google is set up
// again, so while it holds any, force must say that the admin has been
// told.
func (m *Manager) Remove(ctx context.Context, admin jit.Identity, force bool) (Status, error) {
	saved, err := m.load()
	if err != nil {
		return Status{}, err
	}
	if saved == nil {
		return m.Status(), nil
	}
	st := m.Status()
	if st.Source == SourceUI && st.Held > 0 && !force {
		return Status{}, &jit.Error{Code: "conflict", Status: http.StatusConflict, Force: true,
			Message: "jitd still has Google group memberships to look after, for " + plural(st.Held, "request") +
				". Without a key it cannot remove them when the access ends; they stay in Google until Google is set up again. Remove anyway with force."}
	}
	if err := m.Store.DeleteSetting(settingKey); err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	m.saved = nil
	m.mu.Unlock()
	m.log().Info("google settings removed on the Google page", "service_account", st.Account, "by", admin.Login, "requests_still_held", st.Held)
	m.Svc.GoogleCheckNow(ctx)
	return m.Status(), nil
}

func bad(msg string) *jit.Error {
	return &jit.Error{Code: "bad_request", Status: http.StatusBadRequest, Message: msg}
}

// list splits what a form field holds, on commas and white space, into
// lower case entries without repeats.
func list(s string) []string {
	out := []string{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if p = strings.ToLower(p); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// domains reads the allowed domains from the form.
func domains(s string) ([]string, error) {
	out := []string{}
	for _, d := range list(s) {
		d = strings.TrimPrefix(d, "@")
		if !domainRE.MatchString(d) {
			return nil, bad(fmt.Sprintf("Nothing was saved: %q is not an email domain. Name domains like example.com; there is no wildcard.", d))
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out, nil
}

// shown is an allowlist for display: one that was never set allows all.
func shown(list []string) []string {
	if list == nil {
		return []string{jit.DefaultOktaAllowlist}
	}
	return list
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
