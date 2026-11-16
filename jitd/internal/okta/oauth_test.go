package okta

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func rsaPEM(t *testing.T, k *rsa.PrivateKey, pkcs1 bool) string {
	t.Helper()
	if pkcs1 {
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	}
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

// tokenServer is an Okta org whose API takes only the access tokens its
// token endpoint issued, for a client assertion signed by pub.
type tokenServer struct {
	t      *testing.T
	pub    crypto.PublicKey
	org    *fakeOrg
	base   string
	mu     sync.Mutex
	issued int
	valid  map[string]bool
	dpop   bool
	claims map[string]any
	header map[string]any
	scope  string
}

func (s *tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth2/v1/token" {
		s.token(w, r)
		return
	}
	s.mu.Lock()
	ok := s.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`)
		return
	}
	s.org.ServeHTTP(w, r)
}

func (s *tokenServer) token(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(code, desc string) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, code, desc)
	}
	if s.dpop {
		fail("invalid_dpop_proof", "The DPoP proof JWT header is missing.")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail("invalid_request", err.Error())
		return
	}
	if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		fail("invalid_request", "bad grant")
		return
	}
	s.scope = r.Form.Get("scope")
	parts := strings.Split(r.Form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		fail("invalid_client", "not a JWT")
		return
	}
	dec := func(p string, v any) {
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			s.t.Errorf("decoding JWT part: %v", err)
		}
		_ = json.Unmarshal(b, v)
	}
	s.header, s.claims = map[string]any{}, map[string]any{}
	dec(parts[0], &s.header)
	dec(parts[1], &s.claims)
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := s.pub.(type) {
	case *rsa.PublicKey:
		if s.header["alg"] != "RS256" || rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) != nil {
			fail("invalid_client", "bad signature")
			return
		}
	case *ecdsa.PublicKey:
		if s.header["alg"] != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			fail("invalid_client", "bad signature")
			return
		}
	}
	if s.claims["aud"] != s.base+"/oauth2/v1/token" || s.claims["iss"] != "0oaJIT" || s.claims["sub"] != "0oaJIT" {
		fail("invalid_client", fmt.Sprintf("bad claims %v", s.claims))
		return
	}
	s.issued++
	tok := fmt.Sprintf("at-%d", s.issued)
	if s.valid == nil {
		s.valid = map[string]bool{}
	}
	s.valid[tok] = true
	fmt.Fprintf(w, `{"token_type":"Bearer","expires_in":3600,"access_token":%q,"scope":%q}`, tok, s.scope)
}

func newAppOrg(t *testing.T, signer crypto.Signer, keyPEM string, extra map[string]string) (*tokenServer, *HTTP) {
	t.Helper()
	s := &tokenServer{t: t, pub: signer.Public(), org: &fakeOrg{members: map[string]bool{}}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.base = srv.URL
	vars := map[string]string{"OKTA_ORG_URL": srv.URL, "OKTA_CLIENT_ID": "0oaJIT", "OKTA_PRIVATE_KEY": keyPEM}
	for k, v := range extra {
		vars[k] = v
	}
	c, err := NewFromValues(vars)
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func TestOAuthServiceApp(t *testing.T) {
	ctx := context.Background()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, c := newAppOrg(t, k, rsaPEM(t, k, false), map[string]string{"OKTA_PRIVATE_KEY_ID": "kid-1"})

	if u, err := c.FindUser(ctx, "alice@example.com"); err != nil || u.ID != "00uA" {
		t.Fatalf("FindUser = %+v, %v", u, err)
	}
	if err := c.AddMember(ctx, "00gAAAAAAAAAAAA1", "00uA"); err != nil {
		t.Fatal(err)
	}
	if s.issued != 1 {
		t.Errorf("token fetched %d times, want 1 (cached)", s.issued)
	}
	if s.header["kid"] != "kid-1" {
		t.Errorf("kid = %v", s.header["kid"])
	}
	if s.scope != "okta.users.read okta.groups.manage" {
		t.Errorf("scope = %q", s.scope)
	}
	if _, ok := s.claims["jti"]; !ok {
		t.Error("assertion has no jti")
	}
	for _, a := range s.org.auth {
		if a != "Bearer at-1" {
			t.Fatalf("Authorization = %q", a)
		}
	}

	// Okta drops the token early: jitd gets a new one and retries.
	s.mu.Lock()
	s.valid = map[string]bool{}
	s.mu.Unlock()
	if m, err := c.IsMember(ctx, "00gAAAAAAAAAAAA1", "00uA"); err != nil || !m {
		t.Fatalf("IsMember after token revocation = %v, %v", m, err)
	}
	if s.issued != 2 {
		t.Errorf("token fetched %d times, want 2", s.issued)
	}
}

func TestOAuthECKeyAndScopes(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := x509.MarshalECPrivateKey(k)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	// One-line form, as an env file would hold it.
	p = strings.ReplaceAll(strings.TrimSpace(p), "\n", `\n`)
	s, c := newAppOrg(t, k, p, map[string]string{"OKTA_SCOPES": "okta.users.read,okta.groups.manage okta.groups.read"})
	if _, err := c.FindUser(context.Background(), "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if s.header["alg"] != "ES256" || s.scope != "okta.users.read okta.groups.manage okta.groups.read" {
		t.Errorf("alg = %v, scope = %q", s.header["alg"], s.scope)
	}
}

func TestOAuthErrors(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Signed with a key Okta does not know.
	s, c := newAppOrg(t, k, rsaPEM(t, other, true), nil)
	_, err = c.FindUser(context.Background(), "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("wrong key: err = %v", err)
	}
	if len(s.org.calls) != 0 {
		t.Errorf("API called without a token: %v", s.org.calls)
	}

	// DPoP required.
	s.dpop = true
	_, err = c.FindUser(context.Background(), "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "DPoP") {
		t.Errorf("DPoP: err = %v", err)
	}
}

func TestNewFromValuesServiceApp(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	good := rsaPEM(t, k, false)
	org := "https://x.okta.com"
	for _, tc := range []struct {
		name string
		vars map[string]string
		want string // error substring; "" means ok
	}{
		{"app", map[string]string{"OKTA_ORG_URL": org, "OKTA_CLIENT_ID": "0oa1", "OKTA_PRIVATE_KEY": good}, ""},
		{"pkcs1", map[string]string{"OKTA_ORG_URL": org, "OKTA_CLIENT_ID": "0oa1", "OKTA_PRIVATE_KEY": rsaPEM(t, k, true)}, ""},
		{"both", map[string]string{"OKTA_ORG_URL": org, "OKTA_API_TOKEN": "t", "OKTA_CLIENT_ID": "0oa1", "OKTA_PRIVATE_KEY": good}, "not both"},
		{"no key", map[string]string{"OKTA_ORG_URL": org, "OKTA_CLIENT_ID": "0oa1"}, "OKTA_PRIVATE_KEY is not"},
		{"no id", map[string]string{"OKTA_ORG_URL": org, "OKTA_PRIVATE_KEY": good}, "OKTA_CLIENT_ID is not"},
		{"garbage", map[string]string{"OKTA_ORG_URL": org, "OKTA_CLIENT_ID": "0oa1", "OKTA_PRIVATE_KEY": "nope"}, "not a PEM"},
		{"short", map[string]string{"OKTA_ORG_URL": org, "OKTA_CLIENT_ID": "0oa1", "OKTA_PRIVATE_KEY": rsaPEM(t, small, false)}, "2048"},
	} {
		c, err := NewFromValues(tc.vars)
		switch {
		case tc.want == "" && (err != nil || c.OAuth == nil):
			t.Errorf("%s: c = %+v, err = %v", tc.name, c, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
