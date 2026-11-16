package okta

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuth signs jitd in to Okta as an API service app, with the OAuth 2.0
// client credentials flow and a private key (private_key_jwt), instead of an
// API token. Unlike a token, which acts as the admin who created it, a
// service app has its own identity in the Okta system log, only the scopes
// it was granted, and its own admin role.
//
// Set OKTA_CLIENT_ID and OKTA_PRIVATE_KEY (PEM: PKCS#8, PKCS#1 or SEC 1;
// RSA or EC). OKTA_PRIVATE_KEY_ID is the key's kid, needed when the app has
// more than one key; OKTA_SCOPES overrides DefaultScopes.
//
// Okta's "Require Demonstrating Proof of Possession (DPoP)" setting must be
// off for the app: jitd does not send DPoP proofs.
type OAuth struct {
	TokenURL string // https://example.okta.com/oauth2/v1/token
	ClientID string
	KeyID    string
	Scopes   []string

	key crypto.Signer
	alg string

	mu  sync.Mutex
	tok string
	exp time.Time
}

// DefaultScopes are what jitd asks for: finding users, and reading and
// changing group membership (okta.groups.manage includes reading groups).
var DefaultScopes = []string{"okta.users.read", "okta.groups.manage"}

// newOAuth builds the service app client for the org at base.
func newOAuth(base string, vars map[string]string) (*OAuth, error) {
	id := strings.TrimSpace(vars["OKTA_CLIENT_ID"])
	if id == "" {
		return nil, errors.New("OKTA_PRIVATE_KEY is set, but OKTA_CLIENT_ID is not")
	}
	if strings.TrimSpace(vars["OKTA_PRIVATE_KEY"]) == "" {
		return nil, errors.New("OKTA_CLIENT_ID is set, but OKTA_PRIVATE_KEY is not")
	}
	key, alg, err := parsePrivateKey(vars["OKTA_PRIVATE_KEY"])
	if err != nil {
		return nil, fmt.Errorf("OKTA_PRIVATE_KEY: %w", err)
	}
	scopes := strings.Fields(strings.ReplaceAll(vars["OKTA_SCOPES"], ",", " "))
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	return &OAuth{
		TokenURL: base + "/oauth2/v1/token",
		ClientID: id,
		KeyID:    strings.TrimSpace(vars["OKTA_PRIVATE_KEY_ID"]),
		Scopes:   scopes,
		key:      key,
		alg:      alg,
	}, nil
}

// parsePrivateKey reads a PEM private key and picks its JWS algorithm. A
// key whose line breaks were written as literal "\n" (as in a one-line env
// file) is accepted too.
func parsePrivateKey(s string) (crypto.Signer, string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "\n") && strings.Contains(s, `\n`) {
		s = strings.ReplaceAll(s, `\n`, "\n")
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, "", errors.New("not a PEM private key (-----BEGIN PRIVATE KEY----- …)")
	}
	var k any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, "", fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, "", err
	}
	switch k := k.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, "", errors.New("RSA key is shorter than 2048 bits")
		}
		return k, "RS256", nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return k, "ES256", nil
		case elliptic.P384():
			return k, "ES384", nil
		case elliptic.P521():
			return k, "ES512", nil
		}
		return nil, "", errors.New("unsupported EC curve (use P-256, P-384 or P-521)")
	}
	return nil, "", fmt.Errorf("unsupported key type %T (use RSA or EC)", k)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion is the signed JWT that proves jitd holds the app's key.
func (o *OAuth) assertion(now time.Time) (string, error) {
	hdr := map[string]string{"alg": o.alg, "typ": "JWT"}
	if o.KeyID != "" {
		hdr["kid"] = o.KeyID
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": o.ClientID,
		"sub": o.ClientID,
		"aud": o.TokenURL,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": hex.EncodeToString(jti),
	}
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sig, err := o.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

func (o *OAuth) sign(input []byte) ([]byte, error) {
	switch o.alg {
	case "RS256":
		d := sha256.Sum256(input)
		return rsa.SignPKCS1v15(rand.Reader, o.key.(*rsa.PrivateKey), crypto.SHA256, d[:])
	case "ES256", "ES384", "ES512":
		k := o.key.(*ecdsa.PrivateKey)
		var d []byte
		switch o.alg {
		case "ES256":
			s := sha256.Sum256(input)
			d = s[:]
		case "ES384":
			s := sha512.Sum384(input)
			d = s[:]
		default:
			s := sha512.Sum512(input)
			d = s[:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, d)
		if err != nil {
			return nil, err
		}
		// JWS wants r||s, each padded to the curve size.
		n := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*n)
		r.FillBytes(out[:n])
		s.FillBytes(out[n:])
		return out, nil
	}
	return nil, fmt.Errorf("unsupported algorithm %s", o.alg)
}

// token returns a valid access token, fetching a new one shortly before the
// old one expires.
func (o *OAuth) token(ctx context.Context, hc *http.Client) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	if o.tok != "" && now.Before(o.exp) {
		return o.tok, nil
	}
	a, err := o.assertion(now)
	if err != nil {
		return "", fmt.Errorf("okta token: signing the client assertion: %w", err)
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {strings.Join(o.Scopes, " ")},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {a},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jitd")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("okta token: %w", err)
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
		if strings.Contains(tr.Error, "dpop") {
			return "", fmt.Errorf("okta token: %d %s: turn off \"Require Demonstrating Proof of Possession (DPoP)\" for the jitd app in Okta; jitd does not send DPoP proofs", resp.StatusCode, tr.Error)
		}
		if tr.Error != "" {
			return "", fmt.Errorf("okta token: %d %s: %s", resp.StatusCode, tr.Error, tr.Description)
		}
		body := strings.TrimSpace(string(b))
		if len(body) > 512 {
			body = body[:512]
		}
		return "", fmt.Errorf("okta token: %d %s", resp.StatusCode, body)
	}
	if !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", fmt.Errorf("okta token: got a %q token, want Bearer; turn off DPoP for the jitd app in Okta", tr.TokenType)
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	// Renew a minute early (or halfway, for very short tokens).
	early := min(time.Minute, ttl/2)
	o.tok, o.exp = tr.AccessToken, now.Add(ttl-early)
	return o.tok, nil
}

// forget drops tok, so the next call fetches a new one (after Okta rejected
// it, say because the app's key or grants changed).
func (o *OAuth) forget(tok string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.tok == tok {
		o.tok = ""
	}
}
