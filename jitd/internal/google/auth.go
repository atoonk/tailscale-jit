package google

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Key is a service account key, as the JSON file Google hands out when the
// key is created holds it.
type Key struct {
	Email   string // the service account's address (client_email)
	ID      string // which of the account's keys this is (private_key_id); not a secret
	Project string // the Cloud project the account lives in (project_id)
	key     *rsa.PrivateKey
}

// ParseKey reads a service account's JSON key. Its errors never quote the
// key. The file's token_uri is ignored on purpose: jitd signs in at
// Google's token endpoint and nowhere else, so a pasted file cannot make it
// send a signed assertion to another address.
func ParseKey(text string) (*Key, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("the service account key is empty")
	}
	var f struct {
		Type       string `json:"type"`
		Email      string `json:"client_email"`
		PrivateKey string `json:"private_key"`
		KeyID      string `json:"private_key_id"`
		Project    string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(text), &f); err != nil {
		return nil, errors.New("this is not a JSON key file: paste the whole file Google downloaded when the key was created, from { to }")
	}
	switch {
	case f.Type == "":
		return nil, errors.New(`this JSON is not a service account key (it has no "type": "service_account")`)
	case f.Type != "service_account":
		typ := f.Type
		if len(typ) > 40 {
			typ = typ[:40]
		}
		return nil, fmt.Errorf("this is a %q credential, not a service account key: create a JSON key for a service account", typ)
	case !strings.Contains(f.Email, "@"):
		return nil, errors.New("the key file has no client_email (the service account's address)")
	case f.PrivateKey == "":
		return nil, errors.New("the key file has no private_key")
	}
	block, _ := pem.Decode([]byte(f.PrivateKey))
	if block == nil {
		return nil, errors.New("the private_key in the key file is not a PEM block")
	}
	var rk *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, _ = k.(*rsa.PrivateKey)
	} else if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		rk = k
	}
	if rk == nil {
		return nil, errors.New("the private_key in the key file is not an RSA key")
	}
	return &Key{Email: strings.TrimSpace(f.Email), ID: strings.TrimSpace(f.KeyID), Project: strings.TrimSpace(f.Project), key: rk}, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion is the signed JWT that proves jitd holds the account's key.
func (k *Key) assertion(now time.Time, aud string) (string, error) {
	hdr := map[string]string{"alg": "RS256", "typ": "JWT"}
	if k.ID != "" {
		hdr["kid"] = k.ID
	}
	claims := map[string]any{
		"iss":   k.Email,
		"scope": scope,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, d[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// TokenError is Google's token endpoint not signing the service account in.
type TokenError struct {
	Status      int
	Code        string // the OAuth error, such as invalid_grant; empty when the answer was not Google's
	Description string
	Body        string // the answer, cut short, when it was not Google's
}

func (e *TokenError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("google token: %d %s: %s", e.Status, e.Code, e.Description)
	}
	return fmt.Sprintf("google token: %d %s", e.Status, e.Body)
}

// token returns a valid access token, fetching a new one shortly before the
// old one expires.
func (c *HTTP) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.tok != "" && now.Before(c.exp) {
		return c.tok, nil
	}
	a, err := c.Key.assertion(now, c.TokenURL)
	if err != nil {
		return "", fmt.Errorf("google token: signing the assertion: %w", err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {a},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jitd")
	resp, err := c.hc().Do(req)
	if err != nil {
		return "", fmt.Errorf("google token: %w", bare(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(b, &tr)
	if resp.StatusCode/100 != 2 || tr.AccessToken == "" {
		te := &TokenError{Status: resp.StatusCode, Code: tr.Error, Description: tr.Description}
		if te.Code == "" {
			te.Body = short(string(b))
		}
		return "", te
	}
	if tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", fmt.Errorf("google token: got a %q token, want Bearer", tr.TokenType)
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	// Renew a minute early (or halfway, for very short tokens).
	early := min(time.Minute, ttl/2)
	c.tok, c.exp = tr.AccessToken, now.Add(ttl-early)
	return c.tok, nil
}

// forget drops tok, so the next call fetches a new one (after Google
// rejected it, say because the key was deleted).
func (c *HTTP) forget(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok == tok {
		c.tok = ""
	}
}

// unreachable is a call that got no answer from Google.
type unreachable struct{ err error }

func (e *unreachable) Error() string { return e.err.Error() }
func (e *unreachable) Unwrap() error { return e.err }

// bare marks a transport error as such and drops the address from it: it
// can carry a person's email in its query string.
func bare(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return &unreachable{err}
}

func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
