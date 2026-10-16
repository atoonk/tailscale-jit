// Package tsapi is a minimal client for the parts of the Tailscale public API
// that jitd needs: custom device posture attributes and the policy file.
package tsapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// DefaultBaseURL is the Tailscale public API.
const DefaultBaseURL = "https://api.tailscale.com"

// Client is the subset of the Tailscale API used by jitd, so tests can fake it.
type Client interface {
	SetAttribute(ctx context.Context, deviceID, key string, value any, expiry time.Time, comment string) error
	GetAttributes(ctx context.Context, deviceID string) (Attributes, error)
	DeleteAttribute(ctx context.Context, deviceID, key string) error
	GetPolicy(ctx context.Context) (Policy, error)
}

// Attributes is the response of GET /api/v2/device/{id}/attributes.
type Attributes struct {
	Attributes map[string]any       `json:"attributes"`
	Expiries   map[string]time.Time `json:"expiries,omitempty"`
}

// Policy holds the parts of the tailnet policy file jitd reads: groups (to
// resolve group: principals) and postures + grants (to check what each JIT
// posture unlocks).
type Policy struct {
	Groups    map[string][]string `json:"groups"`
	Postures  map[string][]string `json:"postures"`
	Grants    []Grant             `json:"grants"`
	TagOwners map[string][]string `json:"tagOwners"`
}

// Grant is the subset of a policy grant jitd looks at.
type Grant struct {
	Src        []string `json:"src"`
	Dst        []string `json:"dst"`
	SrcPosture []string `json:"srcPosture"`
}

// APIError is a non-2xx response from the Tailscale API.
type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("tailscale API %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

// IsNotFound reports whether err is a 404 from the Tailscale API.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// HTTP implements Client over net/http.
type HTTP struct {
	BaseURL string
	HC      *http.Client // must add authentication
	Timeout time.Duration
}

// CredentialVars are the variables NewFromValues looks at.
var CredentialVars = []string{"TS_API_KEY", "TS_OAUTH_CLIENT_ID", "TS_OAUTH_CLIENT_SECRET"}

// ErrNoCredentials is returned when none of CredentialVars is set.
var ErrNoCredentials = errors.New("no Tailscale API credentials: set TS_API_KEY, or TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET")

// CredentialKind says which credential a set of variables holds: "api_key",
// "oauth", or "" if neither is complete.
func CredentialKind(vars map[string]string) string {
	switch {
	case vars["TS_API_KEY"] != "":
		return "api_key"
	case vars["TS_OAUTH_CLIENT_ID"] != "" && vars["TS_OAUTH_CLIENT_SECRET"] != "":
		return "oauth"
	}
	return ""
}

// NewFromValues builds an authenticated client from TS_API_KEY, or from
// TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET (scopes are fixed on the OAuth
// client in the admin console), taken from vars.
func NewFromValues(ctx context.Context, baseURL string, vars map[string]string) (*HTTP, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	var hc *http.Client
	switch CredentialKind(vars) {
	case "api_key":
		hc = oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: vars["TS_API_KEY"]}))
	case "oauth":
		cfg := clientcredentials.Config{
			ClientID:     vars["TS_OAUTH_CLIENT_ID"],
			ClientSecret: vars["TS_OAUTH_CLIENT_SECRET"],
			TokenURL:     baseURL + "/api/v2/oauth/token",
		}
		hc = cfg.Client(ctx)
	default:
		return nil, ErrNoCredentials
	}
	return &HTTP{BaseURL: baseURL, HC: hc, Timeout: 15 * time.Second}, nil
}

// Switchable is a Client whose backing client can be replaced while jitd
// runs, so credentials fixed through the setup page take effect without a
// restart. Until one is set, every call fails with Unconfigured.
type Switchable struct {
	mu sync.RWMutex
	c  Client
}

// ErrUnconfigured is the error every call returns while no client is set.
var ErrUnconfigured = errors.New("the Tailscale API credentials are not configured or do not work; an admin can fix this on the Setup page (/admin/setup)")

// Set replaces the backing client; nil makes calls fail again.
func (s *Switchable) Set(c Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.c = c
}

func (s *Switchable) get() (Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.c == nil {
		return nil, ErrUnconfigured
	}
	return s.c, nil
}

func (s *Switchable) SetAttribute(ctx context.Context, deviceID, key string, value any, expiry time.Time, comment string) error {
	c, err := s.get()
	if err != nil {
		return err
	}
	return c.SetAttribute(ctx, deviceID, key, value, expiry, comment)
}

func (s *Switchable) GetAttributes(ctx context.Context, deviceID string) (Attributes, error) {
	c, err := s.get()
	if err != nil {
		return Attributes{}, err
	}
	return c.GetAttributes(ctx, deviceID)
}

func (s *Switchable) DeleteAttribute(ctx context.Context, deviceID, key string) error {
	c, err := s.get()
	if err != nil {
		return err
	}
	return c.DeleteAttribute(ctx, deviceID, key)
}

func (s *Switchable) GetPolicy(ctx context.Context) (Policy, error) {
	c, err := s.get()
	if err != nil {
		return Policy{}, err
	}
	return c.GetPolicy(ctx)
}

func attrPath(deviceID, key string) string {
	p := "/api/v2/device/" + url.PathEscape(deviceID) + "/attributes"
	if key != "" {
		p += "/" + url.PathEscape(key)
	}
	return p
}

// SetAttribute creates or updates a custom posture attribute. A zero expiry
// means the attribute does not expire.
func (c *HTTP) SetAttribute(ctx context.Context, deviceID, key string, value any, expiry time.Time, comment string) error {
	body := map[string]any{"value": value}
	if !expiry.IsZero() {
		body["expiry"] = expiry.UTC().Format(time.RFC3339)
	}
	if comment != "" {
		body["comment"] = comment
	}
	return c.do(ctx, http.MethodPost, attrPath(deviceID, key), body, nil)
}

// GetAttributes returns all posture attributes of a device.
func (c *HTTP) GetAttributes(ctx context.Context, deviceID string) (Attributes, error) {
	var a Attributes
	err := c.do(ctx, http.MethodGet, attrPath(deviceID, ""), nil, &a)
	return a, err
}

// DeleteAttribute removes a custom posture attribute from a device.
func (c *HTTP) DeleteAttribute(ctx context.Context, deviceID, key string) error {
	return c.do(ctx, http.MethodDelete, attrPath(deviceID, key), nil, nil)
}

// GetPolicy returns the parts of the tailnet policy file jitd reads (see Policy).
func (c *HTTP) GetPolicy(ctx context.Context) (Policy, error) {
	var p Policy
	err := c.do(ctx, http.MethodGet, "/api/v2/tailnet/-/acl", nil, &p)
	return p, err
}

func (c *HTTP) do(ctx context.Context, method, path string, in, out any) error {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HC.Do(req)
	if err != nil {
		return fmt.Errorf("tailscale API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: msg}
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("tailscale API %s %s: decoding response: %w", method, path, err)
		}
	}
	return nil
}
