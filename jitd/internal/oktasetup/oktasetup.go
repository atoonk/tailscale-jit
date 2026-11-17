// Package oktasetup looks after jitd's Okta credentials: where they come
// from (the environment, the env file, or the Okta page, which keeps them
// in jitd's database), and trying, saving and removing the ones set on the
// page.
package oktasetup

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/okta"
)

// settingKey is where the credentials saved on the page live in the store.
const settingKey = "okta"

// checkTimeout bounds trying credentials against Okta before saving them.
const checkTimeout = 20 * time.Second

// Manager decides which Okta credentials are in force, and changes the ones
// saved on the Okta page.
//
// Credentials in the environment or the env file win: whoever runs the box
// (or the Kubernetes Secret) has the last word, and the page then only
// shows them. The allowlists always come from there, never from the page:
// they are a guard on what an admin in the browser can make jitd do.
type Manager struct {
	Store *jit.Store
	Svc   *jit.Service
	// Env returns the Okta variables set outside the database, credentials
	// and allowlists: the environment and the env file. Nil means none.
	Env func() (map[string]string, error)
	// EnvFile is the env file's path, for the page to name. It may be empty.
	EnvFile string
	// Dial builds a client to try credentials with. It is
	// okta.NewFromValues unless set (the preview and tests use a fake).
	Dial func(vars map[string]string) (okta.Client, error)
	Log  *slog.Logger
	Now  func() time.Time

	once    sync.Once
	mu      sync.Mutex
	saved   *okta.Settings // what the page saved; nil when nothing
	loadErr error
}

// Input is what the Okta page's form sends: the org's address and either a
// service app (client ID and private key) or an API token.
type Input struct {
	OrgURL       string `json:"org_url"`
	ClientID     string `json:"client_id"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	Scopes       string `json:"scopes"`
	APIToken     string `json:"api_token"`
}

// Sources of the credentials in force.
const (
	SourceUI  = "ui"  // saved on the Okta page
	SourceEnv = "env" // the environment or the env file
)

// Ways of signing in.
const (
	AuthServiceApp = "service_app"
	AuthAPIToken   = "api_token"
)

// Status is the Okta connection as the page and GET /v1/okta show it. It
// never carries the private key or the API token.
type Status struct {
	Source  string `json:"source"` // SourceUI, SourceEnv, or "" when Okta is not set up
	EnvFile string `json:"env_file,omitempty"`
	// Shadowed: credentials saved on the page are being ignored, because
	// the environment or the env file sets its own.
	Shadowed bool `json:"shadowed,omitempty"`
	// Enabled: the credentials are complete and well-formed. Whether Okta
	// accepts them is Error.
	Enabled        bool      `json:"enabled"`
	Auth           string    `json:"auth,omitempty"`
	OrgURL         string    `json:"org_url,omitempty"`
	ClientID       string    `json:"client_id,omitempty"`
	KeyID          string    `json:"key_id,omitempty"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	TokenHint      string    `json:"token_hint,omitempty"`
	Scopes         []string  `json:"scopes,omitempty"`
	SavedBy        string    `json:"saved_by,omitempty"`
	SavedAt        time.Time `json:"saved_at,omitzero"`
	// CheckedAt is when jitd last tried the credentials against Okta.
	// Error and Fix say what is wrong, if anything, and what to do.
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Error     string    `json:"error,omitempty"`
	Fix       string    `json:"fix,omitempty"`
	// The allowlists in force ("*" is every group; empty is none).
	GrantAllowlist []string `json:"grant_allowlist"`
	ReadAllowlist  []string `json:"read_allowlist"`
	// Held counts the requests whose Okta memberships jitd still has to
	// look after. It cannot remove them while Okta is off.
	Held int `json:"held"`
}

// Configured reports whether there are Okta credentials at all.
func (st Status) Configured() bool { return st.Source != "" }

// Working reports whether the credentials were tried and Okta took them.
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
func (m *Manager) load() (*okta.Settings, error) {
	m.once.Do(func() {
		var s okta.Settings
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

// Vars returns the Okta variables in force, for okta.Dynamic: the ones from
// the environment and the env file if they hold credentials, otherwise the
// credentials saved on the page with the allowlists from outside.
func (m *Manager) Vars() (map[string]string, error) {
	env, err := m.env()
	if err != nil {
		return nil, err
	}
	if okta.Configured(env) {
		return env, nil
	}
	saved, err := m.load()
	if err != nil {
		return nil, err
	}
	if saved == nil {
		return env, nil
	}
	vars := saved.Vars()
	for k, v := range env {
		if _, credential := vars[k]; !credential {
			vars[k] = v
		}
	}
	return vars, nil
}

// Status describes the connection.
func (m *Manager) Status() Status {
	st := Status{EnvFile: m.EnvFile, GrantAllowlist: []string{}, ReadAllowlist: []string{}}
	state := m.Svc.OktaState()
	st.Enabled, st.Held = state.Enabled, state.Held
	if m.Svc.OktaLimits != nil {
		lim := m.Svc.OktaLimits()
		st.GrantAllowlist, st.ReadAllowlist = shown(lim.Grant), shown(lim.Read)
	}
	env, err := m.env()
	if err != nil {
		// The env file cannot be read, so jitd cannot tell what it sets.
		st.Source = SourceEnv
		st.Error = "jitd cannot read its Okta settings: " + err.Error()
		st.Fix = "Fix the env file. Until then jitd carries on with the settings it read last, if it has read any since it started."
		return st
	}
	saved, err := m.load()
	if err != nil {
		st.Error = "jitd cannot read the Okta credentials saved here from its database: " + err.Error()
		return st
	}
	vars := env
	switch {
	case okta.Configured(env):
		st.Source, st.Shadowed = SourceEnv, saved != nil
	case saved != nil:
		st.Source, vars = SourceUI, saved.Vars()
		st.SavedBy, st.SavedAt = saved.SavedBy, saved.SavedAt
	default:
		return st
	}
	st.OrgURL = strings.TrimSuffix(strings.TrimSpace(vars["OKTA_ORG_URL"]), "/")
	if tok := strings.TrimSpace(vars["OKTA_API_TOKEN"]); tok != "" {
		st.Auth, st.TokenHint = AuthAPIToken, hint(tok)
	} else {
		st.Auth = AuthServiceApp
		st.ClientID = strings.TrimSpace(vars["OKTA_CLIENT_ID"])
		st.KeyID = strings.TrimSpace(vars["OKTA_PRIVATE_KEY_ID"])
		st.KeyFingerprint = okta.KeyFingerprint(vars["OKTA_PRIVATE_KEY"])
		st.Scopes = scopes(vars["OKTA_SCOPES"])
	}
	switch {
	case !state.Enabled:
		st.Error = "These credentials cannot be used: " + state.Off
		if st.Source == SourceEnv {
			st.Fix = "Fix them where they are set; jitd reads them again on its own."
		} else {
			st.Fix = "Replace them below."
		}
	case state.Err != nil:
		st.Error, st.Fix = okta.Explain(state.Err, st.Auth == AuthServiceApp)
	}
	if state.Enabled {
		st.CheckedAt = state.CheckedAt
	}
	return st
}

// Save tries the credentials against Okta and, only if Okta takes them,
// stores them. They are in force from the next Okta call on.
func (m *Manager) Save(ctx context.Context, admin jit.Identity, in Input) (Status, error) {
	if m.Status().Source == SourceEnv {
		return Status{}, &jit.Error{Code: "conflict", Status: http.StatusConflict,
			Message: "Okta is set up in jitd's environment or env file (OKTA_ORG_URL and the rest); change it there"}
	}
	s, err := clean(in)
	if err != nil {
		return Status{}, err
	}
	vars := s.Vars()
	dial := m.Dial
	if dial == nil {
		dial = func(vars map[string]string) (okta.Client, error) { return okta.NewFromValues(vars) }
	}
	c, err := dial(vars)
	if err != nil {
		// What is wrong with the values themselves, in the page's words.
		msg := strings.NewReplacer("OKTA_PRIVATE_KEY: ", "the private key cannot be used: ", "OKTA_ORG_URL", "the Okta address").Replace(err.Error())
		return Status{}, bad("Nothing was saved: " + msg)
	}
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	if err := c.Check(cctx); err != nil {
		what, fix := okta.Explain(err, s.APIToken == "")
		if u, perr := url.Parse(s.OrgURL); perr == nil && strings.Contains(u.Hostname(), "-admin.") {
			fix = strings.TrimSpace(fix + " The address you entered looks like the admin console's: leave out -admin.")
		}
		return Status{}, bad(strings.TrimSpace("Nothing was saved. " + what + " " + fix))
	}
	s.SavedBy, s.SavedAt = admin.Login, m.now().UTC()
	if err := m.Store.PutSetting(settingKey, s); err != nil {
		return Status{}, err
	}
	m.load() // so that a first save does not get overwritten by a late first read
	m.mu.Lock()
	m.saved, m.loadErr = &s, nil
	m.mu.Unlock()
	auth := AuthServiceApp
	if s.APIToken != "" {
		auth = AuthAPIToken
	}
	m.log().Info("okta credentials saved on the Okta page", "org", s.OrgURL, "auth", auth, "by", admin.Login)
	m.Svc.OktaCheckNow(ctx)
	return m.Status(), nil
}

// Remove forgets the credentials saved on the page. Memberships jitd added
// stay its to remove, and it cannot until Okta is set up again, so while it
// holds any, force must say that the admin has been told.
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
		return Status{}, &jit.Error{Code: "conflict", Status: http.StatusConflict,
			Message: "jitd still has Okta group memberships to look after, for " + plural(st.Held, "request") +
				". Without credentials it cannot remove them when the access ends; they stay in Okta until Okta is set up again. Remove anyway with force."}
	}
	if err := m.Store.DeleteSetting(settingKey); err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	m.saved = nil
	m.mu.Unlock()
	m.log().Info("okta credentials removed on the Okta page", "org", saved.OrgURL, "by", admin.Login, "requests_still_held", st.Held)
	m.Svc.OktaCheckNow(ctx)
	return m.Status(), nil
}

// clean checks the form's values and puts them in the shape jitd stores.
func clean(in Input) (okta.Settings, error) {
	s := okta.Settings{
		OrgURL:       strings.TrimSuffix(strings.TrimSpace(in.OrgURL), "/"),
		ClientID:     strings.TrimSpace(in.ClientID),
		PrivateKey:   strings.TrimSpace(in.PrivateKey),
		PrivateKeyID: strings.TrimSpace(in.PrivateKeyID),
		Scopes:       strings.Join(scopes(in.Scopes), " "),
		APIToken:     strings.TrimSpace(in.APIToken),
	}
	if s.OrgURL == "" {
		return s, bad("fill in the Okta address, like https://example.okta.com")
	}
	if !strings.Contains(s.OrgURL, "://") {
		s.OrgURL = "https://" + s.OrgURL
	}
	if u, err := url.Parse(s.OrgURL); err == nil && u.Host != "" {
		// Only the org matters; a pasted page address has a path too.
		s.OrgURL = u.Scheme + "://" + u.Host
	}
	app := s.ClientID != "" || s.PrivateKey != ""
	switch {
	case s.APIToken != "" && app:
		return s, bad("fill in either the service app (client ID and private key) or the API token, not both")
	case s.APIToken != "":
		s.PrivateKeyID, s.Scopes = "", ""
	case s.ClientID == "":
		return s, bad("fill in the client ID (on the app's General tab in Okta; it starts with 0oa)")
	case s.PrivateKey == "":
		return s, bad("paste the private key: the whole PEM block, from -----BEGIN PRIVATE KEY----- to -----END PRIVATE KEY-----")
	}
	return s, nil
}

func bad(msg string) *jit.Error {
	return &jit.Error{Code: "bad_request", Status: http.StatusBadRequest, Message: msg}
}

// hint is the end of a token, enough to tell which one is in use.
func hint(tok string) string {
	if len(tok) <= 8 {
		return "…"
	}
	return "…" + tok[len(tok)-4:]
}

func scopes(s string) []string {
	return strings.Fields(strings.ReplaceAll(s, ",", " "))
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
