// Package setup checks that jitd is installed right: that Tailscale API
// credentials are present and actually work for what jitd does with them.
// The admin Setup page shows the result and says what to fix, without ever
// showing the credentials themselves.
package setup

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// Node describes the tsnet node jitd runs as.
type Node struct {
	ID      string   `json:"id,omitempty"` // stable node ID, e.g. nABC123CNTRL
	DNSName string   `json:"dns_name,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

// Check is one step of the setup check.
type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"` // not run because an earlier step failed
	Detail  string `json:"detail,omitempty"`  // what was found, or the error
	Fix     string `json:"fix,omitempty"`     // what to do about it
}

// Credentials says where the credentials came from, never what they are.
type Credentials struct {
	Kind       string `json:"kind"` // "oauth", "api_key", "federated" or ""
	File       string `json:"file"` // the file jitd reads them from
	FileExists bool   `json:"file_exists"`
	FileError  string `json:"file_error,omitempty"`
	// FileWarning is set when the file can be read by other users.
	FileWarning string   `json:"file_warning,omitempty"`
	FromFile    []string `json:"from_file,omitempty"` // variable names found in the file
	FromEnv     []string `json:"from_env,omitempty"`  // variable names taken from the environment

	// Source is "env" when the credential comes from the file or the
	// environment, "ui" when it was saved on the page, "" when there is none.
	Source string `json:"source,omitempty"`
	// CanSave: this jitd keeps credentials pasted on the page.
	CanSave bool `json:"can_save,omitempty"`
	// What was saved on the page, never the secret: the OAuth client's ID,
	// or the last four characters of an API access token.
	ClientID string    `json:"client_id,omitempty"`
	KeyHint  string    `json:"key_hint,omitempty"`
	SavedBy  string    `json:"saved_by,omitempty"`
	SavedAt  time.Time `json:"saved_at,omitzero"`
	// Shadowed: a credential is saved on the page, but the file or the
	// environment sets one too, and that one wins.
	Shadowed   bool   `json:"shadowed,omitempty"`
	SavedError string `json:"saved_error,omitempty"` // the saved one could not be read
}

// Input is a credential pasted on the page: an OAuth client, or an API
// access token.
type Input struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	APIKey       string `json:"api_key"`
}

// saved is what the settings table keeps under settingKey.
type saved struct {
	ClientID     string    `json:"client_id,omitempty"`
	ClientSecret string    `json:"client_secret,omitempty"`
	APIKey       string    `json:"api_key,omitempty"`
	SavedBy      string    `json:"saved_by,omitempty"`
	SavedAt      time.Time `json:"saved_at"`
}

const settingKey = "tailscale"

func (s saved) vars() map[string]string {
	if s.APIKey != "" {
		return map[string]string{"TS_API_KEY": s.APIKey}
	}
	return map[string]string{"TS_OAUTH_CLIENT_ID": s.ClientID, "TS_OAUTH_CLIENT_SECRET": s.ClientSecret}
}

// Result is what the last check found.
type Result struct {
	CheckedAt   time.Time   `json:"checked_at"`
	OK          bool        `json:"ok"`
	Credentials Credentials `json:"credentials"`
	Node        Node        `json:"node"`
	Tag         string      `json:"tag"` // the tag the node should carry
	Checks      []Check     `json:"checks"`
	// Transient: a check failed for a reason that says nothing about the
	// credential (network error, 5xx, node not known yet). The credential
	// stays in use and the check is worth retrying.
	Transient bool `json:"transient,omitempty"`
}

// Checker runs the setup check and keeps the last result.
type Checker struct {
	EnvFile string // KEY=VALUE file with the credentials; may not exist
	// Store keeps a credential pasted on the page (Save); nil means the file
	// and the environment are the only sources. Those win when they hold one.
	Store   *jit.Store
	APIBase string
	Tag     string // the tag the node should run as, e.g. "tag:jit"
	// Node returns the node jitd runs as; nil or an error means unknown.
	Node func(ctx context.Context) (Node, error)
	// NewClient builds a client from credential variables; tsapi.NewFromValues
	// if nil.
	NewClient func(ctx context.Context, base string, vars map[string]string) (tsapi.Client, error)
	// Target receives the client after a check, and nil only after a check
	// that rejected the credential outright (missing, unreadable, 401/403).
	// A transient failure keeps the new client in use.
	Target *tsapi.Switchable
	Log    *slog.Logger

	run1 sync.Mutex // one check at a time
	mu   sync.Mutex // guards last only, so pages never wait on a running check
	last *Result
}

// selfCheckKey is the attribute written to jitd's own node to prove write
// access; it is deleted straight away.
const selfCheckKey = jit.AttrPrefix + jit.ReservedAttribute

// Last returns the most recent result, or nil if no check has run yet.
func (c *Checker) Last() *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// Run re-reads the credentials and checks them against the Tailscale API.
func (c *Checker) Run(ctx context.Context) *Result {
	c.run1.Lock()
	defer c.run1.Unlock()
	return c.runAndKeep(ctx)
}

// runAndKeep is Run for a caller that holds run1.
func (c *Checker) runAndKeep(ctx context.Context) *Result {
	res := c.run(ctx)
	c.mu.Lock()
	c.last = res
	c.mu.Unlock()
	if c.Log != nil {
		if res.OK {
			c.Log.Info("setup check passed", "credentials", res.Credentials.Kind, "file", res.Credentials.File)
		} else {
			for _, ch := range res.Checks {
				if !ch.OK && !ch.Skipped {
					c.Log.Warn("setup check failed", "check", ch.Name, "detail", ch.Detail, "fix", ch.Fix)
				}
			}
		}
	}
	return res
}

func (c *Checker) run(ctx context.Context) *Result {
	// Credentials: the file first, the environment for anything it lacks,
	// and the one saved on the page when those hold none.
	vars, cred := c.credentials()
	return c.check(ctx, vars, cred, c.hint(cred), c.setTarget)
}

// hint says where to put a working credential, for the fix under a failed
// check.
func (c *Checker) hint(cred Credentials) string {
	file := fmt.Sprintf("put TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET in %s (one KEY=VALUE per line), then click Check again.", cred.File)
	switch {
	case cred.Source == "ui":
		return "Paste a working one under Replace the credential on this page."
	case c.Store != nil && cred.Kind == "" && cred.FileError == "":
		return "Paste an OAuth client under Connect Tailscale on this page, or " + file
	}
	return "P" + file[1:]
}

// check tries vars against the Tailscale API the way an approval uses
// them. adopt receives the client to serve with afterwards, or nil when
// the credential was rejected outright.
func (c *Checker) check(ctx context.Context, vars map[string]string, cred Credentials, fileHint string, adopt func(tsapi.Client)) *Result {
	res := &Result{CheckedAt: time.Now(), Tag: c.Tag, Credentials: cred}
	// Detached from the caller: an admin leaving the page mid-check must not
	// turn into a "could not reach the API" result.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()

	step := func(name string, ok bool, detail, fix string) bool {
		res.Checks = append(res.Checks, Check{Name: name, OK: ok, Detail: detail, Fix: fix})
		return ok
	}
	skip := func(names ...string) {
		for _, n := range names {
			res.Checks = append(res.Checks, Check{Name: n, Skipped: true})
		}
	}

	if c.Node != nil {
		if n, err := c.Node(ctx); err == nil {
			res.Node = n
		}
	}
	// rejected records whether an error rejected the credential itself, as
	// opposed to the API being unreachable or failing for a while.
	rejected := false
	fix := func(err error, scope string) string {
		if cred.Kind == "federated" && tokenRefused(err) {
			return "Tailscale refused the identity token. Check that TS_OAUTH_CLIENT_ID is the federated identity's client ID, and that the token's issuer, subject and audience are the ones the federated identity expects (admin console, Settings → Trust credentials). Then click Check again."
		}
		return fixFor(err, scope, fileHint)
	}
	fail := func(name string, err error, scope string) bool {
		if credentialRejected(err) {
			rejected = true
		} else {
			res.Transient = true
		}
		return step(name, false, describe(err), fix(err, scope))
	}
	if c.Tag != "" && res.Node.ID != "" && !slices.Contains(res.Node.Tags, c.Tag) {
		step("Node tag", false, fmt.Sprintf("this node is not tagged %s (tags: %s)", c.Tag, strings.Join(res.Node.Tags, ", ")),
			fmt.Sprintf("Grants to %s will not reach it. Create an auth key tagged %s, remove the node state directory and restart jitd with TS_AUTHKEY set, or tag the node in the admin console.", c.Tag, c.Tag))
	} else if res.Node.ID != "" {
		step("Node tag", true, fmt.Sprintf("tagged %s", c.Tag), "")
	}

	kindName := map[string]string{"oauth": "OAuth client", "api_key": "API access token", "federated": "federated identity"}
	switch {
	case cred.FileError != "":
		step("Credentials", false, cred.FileError, "Fix the file so jitd can read it (it needs KEY=VALUE lines, readable by the user jitd runs as), then click Check again.")
	case cred.Kind == "":
		detail := "no credentials found"
		if !cred.FileExists {
			detail = fmt.Sprintf("%s does not exist and the environment has no credentials", cred.File)
		} else if len(cred.FromFile) > 0 {
			detail = fmt.Sprintf("%s sets %s, which is not a complete credential", cred.File, strings.Join(cred.FromFile, " and "))
		}
		step("Credentials", false, detail, fileHint)
	default:
		src := []string{}
		if len(cred.FromFile) > 0 {
			src = append(src, strings.Join(cred.FromFile, " and ")+" from "+cred.File)
		}
		if len(cred.FromEnv) > 0 {
			src = append(src, strings.Join(cred.FromEnv, " and ")+" from the environment")
		}
		if cred.Source == "ui" {
			src = append(src, "saved on this page")
		}
		fix := ""
		if cred.Kind == "api_key" {
			fix = "API access tokens expire after at most 90 days; an OAuth client does not. Consider switching before this one expires."
		}
		step("Credentials", true, kindName[cred.Kind]+": "+strings.Join(src, "; "), fix)
	}
	if cred.Kind == "" || cred.FileError != "" {
		skip("Policy file read", "Posture attributes read", "Posture attributes write")
		adopt(nil)
		return res
	}

	newClient := c.NewClient
	if newClient == nil {
		newClient = func(ctx context.Context, base string, vars map[string]string) (tsapi.Client, error) {
			return tsapi.NewFromValues(ctx, base, vars)
		}
	}
	// Build the client with a context that outlives this check: it goes on
	// serving requests. Checks themselves use the bounded ctx.
	client, err := newClient(context.WithoutCancel(ctx), c.APIBase, vars)
	if err != nil {
		step("Policy file read", false, err.Error(), fileHint)
		skip("Posture attributes read", "Posture attributes write")
		adopt(nil)
		return res
	}

	// Policy read: proves the credential is accepted at all, and the
	// policy_file read scope that group: principals need.
	ok := true
	if p, err := client.GetPolicy(ctx); err != nil {
		ok = fail("Policy file read", err, "policy_file (read)")
	} else {
		groups := fmt.Sprintf("%d groups", len(p.Groups))
		if len(p.Groups) == 1 {
			groups = "1 group"
		}
		step("Policy file read", true, "read the policy file: "+groups, "")
	}
	if res.Node.ID == "" {
		step("Posture attributes read", false, "this node's ID is unknown, so the attribute checks cannot run", "")
		skip("Posture attributes write")
		ok = false
		res.Transient = true
	} else {
		if a, err := client.GetAttributes(ctx, res.Node.ID); err != nil {
			ok = fail("Posture attributes read", err, "devices:posture_attributes (read)")
			skip("Posture attributes write")
		} else {
			step("Posture attributes read", true, fmt.Sprintf("read this node's attributes (%d custom)", countCustom(a)), "")
			// Write then delete a throwaway attribute on this node: the same
			// calls an approval makes, on the one device nobody is granted
			// access through.
			if err := client.SetAttribute(ctx, res.Node.ID, selfCheckKey, true, time.Now().Add(2*time.Minute), "jitd setup check"); err != nil {
				// Reads worked, so the credential stays in use even if it
				// cannot write: group lookups (and with them admin access to
				// this page) keep working while the scope is fixed.
				if !credentialRejected(err) {
					res.Transient = true
				}
				ok = step("Posture attributes write", false, describe(err), fix(err, "devices:posture_attributes (write)"))
			} else if err := client.DeleteAttribute(ctx, res.Node.ID, selfCheckKey); err != nil {
				ok = step("Posture attributes write", false, "set "+selfCheckKey+" but could not delete it: "+describe(err), "")
			} else {
				step("Posture attributes write", true, "set and removed "+selfCheckKey+" on this node", "")
			}
		}
	}
	res.OK = ok && allOK(res.Checks)
	if rejected {
		adopt(nil)
	} else {
		// It works, or nothing said it does not (the API was unreachable):
		// serve with it. A wrong node tag does not affect API calls.
		adopt(client)
	}
	return res
}

func (c *Checker) setTarget(cl tsapi.Client) {
	if c.Target != nil {
		c.Target.Set(cl)
	}
}

func allOK(cs []Check) bool {
	for _, c := range cs {
		if !c.OK {
			return false
		}
	}
	return true
}

func countCustom(a tsapi.Attributes) int {
	n := 0
	for k := range a.Attributes {
		if strings.HasPrefix(k, "custom:") {
			n++
		}
	}
	return n
}

// credentials reads the env file and fills in from the environment.
func (c *Checker) credentials() (map[string]string, Credentials) {
	cred := Credentials{File: c.EnvFile}
	vars := map[string]string{}
	if c.EnvFile != "" {
		fromFile, err := ReadEnvFile(c.EnvFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			cred.FileError = err.Error()
		default:
			cred.FileExists = true
			if fi, err := os.Stat(c.EnvFile); err == nil && fi.Mode().Perm()&0o077 != 0 {
				cred.FileWarning = fmt.Sprintf("%s can be read by other users on this host (mode %04o); run chmod 600 %s", c.EnvFile, fi.Mode().Perm(), c.EnvFile)
			}
			for _, k := range tsapi.CredentialVars {
				if v := fromFile[k]; v != "" {
					vars[k] = v
					cred.FromFile = append(cred.FromFile, k)
				}
			}
		}
	}
	for _, k := range tsapi.CredentialVars {
		if vars[k] == "" {
			if v := os.Getenv(k); v != "" {
				vars[k] = v
				cred.FromEnv = append(cred.FromEnv, k)
			}
		}
	}
	cred.Kind = tsapi.CredentialKind(vars)
	if cred.Kind != "" {
		cred.Source = "env"
	}
	if c.Store == nil {
		return vars, cred
	}
	cred.CanSave = true
	var s saved
	switch found, err := c.Store.GetSetting(settingKey, &s); {
	case err != nil:
		cred.SavedError = err.Error()
	case !found:
	case cred.Kind != "" || cred.FileError != "":
		// The file and the environment win, and an unreadable file may
		// well hold one: whoever runs the host has the last word.
		cred.Shadowed = true
	default:
		vars = s.vars()
		cred.Kind, cred.Source = tsapi.CredentialKind(vars), "ui"
		cred.FromFile, cred.FromEnv = nil, nil
		cred.ClientID, cred.KeyHint = s.ClientID, lastFour(s.APIKey)
		cred.SavedBy, cred.SavedAt = s.SavedBy, s.SavedAt
	}
	return vars, cred
}

func lastFour(secret string) string {
	if len(secret) < 12 {
		return ""
	}
	return "…" + secret[len(secret)-4:]
}

// apiChecks are the checks that try the credential itself.
var apiChecks = []string{"Policy file read", "Posture attributes read", "Posture attributes write"}

// Save tries a credential pasted on the page against the Tailscale API
// and keeps it only if every check passes; jitd then serves with it. The
// result of a refused one says which check failed.
func (c *Checker) Save(ctx context.Context, by string, in Input) (*Result, error) {
	if c.Store == nil {
		return nil, &jit.Error{Code: "not_found", Status: http.StatusNotFound, Message: "this jitd does not keep credentials; set them in its env file"}
	}
	bad := func(msg string) (*Result, error) {
		return nil, &jit.Error{Code: "bad_request", Status: http.StatusBadRequest, Message: msg}
	}
	s := saved{ClientID: strings.TrimSpace(in.ClientID), ClientSecret: strings.TrimSpace(in.ClientSecret), APIKey: strings.TrimSpace(in.APIKey), SavedBy: by, SavedAt: time.Now().UTC()}
	switch {
	case s.APIKey != "" && (s.ClientID != "" || s.ClientSecret != ""):
		return bad("Paste an OAuth client or an API access token, not both.")
	case s.APIKey == "" && (s.ClientID == "" || s.ClientSecret == ""):
		return bad("Paste both the OAuth client's ID and its secret.")
	case strings.HasPrefix(s.ClientID, "tskey-client-") && !strings.HasPrefix(s.ClientSecret, "tskey-client-"):
		return bad("That looks like the secret in the client ID field: the secret starts with tskey-client-, the client ID is the short one.")
	}
	c.run1.Lock()
	defer c.run1.Unlock()
	if _, cur := c.credentials(); cur.Source == "env" || cur.FileError != "" {
		return nil, &jit.Error{Code: "conflict", Status: http.StatusConflict,
			Message: fmt.Sprintf("The Tailscale credential is set in %s or in jitd's environment, and that one wins. Change it there, or take it out there first.", c.EnvFile)}
	}
	vars := s.vars()
	tried := c.check(ctx, vars, Credentials{File: c.EnvFile, Kind: tsapi.CredentialKind(vars), Source: "ui", CanSave: true}, "Nothing was saved.", func(tsapi.Client) {})
	for _, name := range apiChecks {
		for _, ch := range tried.Checks {
			if ch.Name != name || ch.OK {
				continue
			}
			msg := name + " failed"
			if ch.Skipped {
				msg = name + " could not run"
			}
			if ch.Detail != "" {
				msg += ": " + ch.Detail
			}
			return bad(strings.TrimSpace(msg + ". " + cmp.Or(ch.Fix, "Nothing was saved.")))
		}
	}
	if err := c.Store.PutSetting(settingKey, s); err != nil {
		return nil, err
	}
	if c.Log != nil {
		c.Log.Info("Tailscale API credential saved on the setup page", "by", by, "kind", tsapi.CredentialKind(vars))
	}
	return c.runAndKeep(ctx), nil
}

// Remove forgets the credential saved on the page. Approvals, revokes and
// clean-up fail until there is one again, unless the file or the
// environment holds one.
func (c *Checker) Remove(ctx context.Context, by string) (*Result, error) {
	if c.Store == nil {
		return nil, &jit.Error{Code: "not_found", Status: http.StatusNotFound, Message: "this jitd does not keep credentials"}
	}
	c.run1.Lock()
	defer c.run1.Unlock()
	if err := c.Store.DeleteSetting(settingKey); err != nil {
		return nil, err
	}
	if c.Log != nil {
		c.Log.Warn("Tailscale API credential saved on the setup page removed", "by", by)
	}
	return c.runAndKeep(ctx), nil
}

// OptionalEnvFile reads an env file that need not exist. One that has not
// been there since jitd started reads as empty: the settings then come
// from the pages and the environment. One that was read and is gone
// afterwards is an error, like one that cannot be read: the lists it held
// limit what jitd may do, so losing the file (a removed file, a volume that
// did not mount) must not lift them. The caller carries on with what it
// read last.
type OptionalEnvFile struct {
	Path string

	mu   sync.Mutex
	seen bool // the file was read at least once
}

// Read returns what the file sets.
func (f *OptionalEnvFile) Read() (map[string]string, error) {
	vars, err := ReadEnvFile(f.Path)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case err == nil:
		f.seen = true
		return vars, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	case f.seen:
		return nil, fmt.Errorf("the env file %s was there when jitd read it earlier and is gone now; put it back, or restart jitd to run without it", f.Path)
	}
	return map[string]string{}, nil
}

// ReadEnvFile parses KEY=VALUE lines. Blank lines and # comments are
// ignored, a leading "export " is allowed, and values may be quoted.
func ReadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return nil, fmt.Errorf("%s line %d: expected KEY=VALUE", path, n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// describe turns an API error into one line for the page, with the response
// body cut short (it can be long).
func describe(err error) string {
	var ae *tsapi.APIError
	if errors.As(err, &ae) {
		body := strings.TrimSpace(ae.Body)
		if len(body) > 160 {
			body = body[:160] + "…"
		}
		return fmt.Sprintf("%s %s returned %d %s", ae.Method, ae.Path, ae.Status, body)
	}
	return err.Error()
}

// fixFor says what to do about an API error: the scope to add, or the
// credential to replace.
func fixFor(err error, scope, fileHint string) string {
	var ae *tsapi.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusForbidden:
			return fmt.Sprintf("The credential works but lacks the %s scope. Create a new OAuth client with it in the admin console (Settings → Trust credentials → New credential → OAuth); scopes cannot be added to an existing one. %s", scope, fileHint)
		case http.StatusUnauthorized:
			return "The credential was rejected: it is wrong, revoked or expired. " + fileHint
		}
		return ""
	}
	if credentialRejected(err) {
		return "The OAuth client ID or secret is wrong, or the client was revoked. " + fileHint
	}
	var ute *json.UnmarshalTypeError
	var se *json.SyntaxError
	if errors.As(err, &ute) || errors.As(err, &se) {
		return "The credential works and the Tailscale API answered, but jitd could not read the response: it uses syntax this version of jitd does not know. Nothing is wrong with your credential or this host; please report this as a jitd bug."
	}
	return "Could not reach the Tailscale API, or it failed for a moment. jitd keeps the credential and retries; check this host's internet access if it persists."
}

// tokenRefused reports whether the token endpoint itself turned the
// credential down, before any API call was made with it.
func tokenRefused(err error) bool {
	var re *oauth2.RetrieveError
	return errors.As(err, &re) && credentialRejected(err)
}

// credentialRejected reports whether err says the credential itself is no
// good (a 401/403 from the API, or the OAuth token endpoint refusing the
// client), as opposed to the API being unreachable or failing for a while
// (network errors, 5xx), which says nothing about the credential.
func credentialRejected(err error) bool {
	var ae *tsapi.APIError
	if errors.As(err, &ae) {
		return ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) && re.Response != nil {
		switch re.Response.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			return true
		}
	}
	return false
}
