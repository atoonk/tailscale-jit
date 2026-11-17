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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

const account = "jitd@proj-1.iam.gserviceaccount.com"

// keyJSON is a key file as Google writes it, with extra fields of ours.
func keyJSON(t *testing.T, extra map[string]string) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey(t))
	if err != nil {
		t.Fatal(err)
	}
	f := map[string]string{
		"type":           "service_account",
		"project_id":     "proj-1",
		"private_key_id": "kid123",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   account,
		"token_uri":      "https://oauth2.googleapis.com/token",
	}
	for k, v := range extra {
		f[k] = v
	}
	b, _ := json.Marshal(f)
	return string(b)
}

// server is a small Cloud Identity: groups by ID, members by email.
type server struct {
	t  *testing.T
	mu sync.Mutex
	ts *httptest.Server

	groups  map[string]string          // ID -> email
	dynamic map[string]bool            // ID -> a dynamic group
	members map[string]map[string]bool // ID -> email -> member

	tokens    int    // tokens handed out
	tokenFail string // if set, the token endpoint answers 400 with this JSON
	reject    int    // answer this many API calls with 401
	disabled  bool   // the API is not enabled
	blind     bool   // the service account sees no group (no role)
	missCode  int    // what a lookup of a non-member answers: 404 (default) or 403
	flaky     int    // answer this many API calls with 503
	pending   int    // how many times an operation answers "not done"
	opError   string // operations finish with this error
	conflict  bool   // create answers 409 without adding
	calls     []string
}

func newServer(t *testing.T) (*server, *HTTP) {
	s := &server{t: t, groups: map[string]string{}, dynamic: map[string]bool{}, members: map[string]map[string]bool{}, missCode: 404}
	s.ts = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.ts.Close)
	k, err := ParseKey(keyJSON(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	c := &HTTP{Key: k, BaseURL: s.ts.URL, TokenURL: s.ts.URL + "/token", Timeout: 5 * time.Second, Wait: 2 * time.Second, Backoff: time.Millisecond}
	return s, c
}

func (s *server) group(id, email string, members ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[id] = email
	s.members[id] = map[string]bool{}
	for _, m := range members {
		s.members[id][m] = true
	}
}

func (s *server) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.calls
	s.calls = nil
	return out
}

func gerr(w http.ResponseWriter, code int, status, msg, reason string) {
	e := map[string]any{"code": code, "message": msg, "status": status}
	if reason != "" {
		e["details"] = []map[string]string{{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason}}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": e})
}

func memberID(email string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(email))
}

func (s *server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/token" {
		s.token(w, r)
		return
	}
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
		gerr(w, 401, "UNAUTHENTICATED", "no token", "")
		return
	}
	switch {
	case s.reject > 0:
		s.reject--
		gerr(w, 401, "UNAUTHENTICATED", "Request had invalid authentication credentials.", "")
		return
	case s.flaky > 0:
		s.flaky--
		gerr(w, 503, "UNAVAILABLE", "The service is currently unavailable.", "")
		return
	case s.disabled:
		gerr(w, 403, "PERMISSION_DENIED", "Cloud Identity API has not been used in project 123 before or it is disabled.", "SERVICE_DISABLED")
		return
	}
	denied := func() {
		gerr(w, 403, "PERMISSION_DENIED", "Error(2028): Permission denied for resource (or it may not exist).", "")
	}
	done := func() {
		if s.pending > 0 {
			json.NewEncoder(w).Encode(map[string]any{"name": "operations/op1", "done": false})
			return
		}
		s.finish(w)
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(p, "/")
	switch {
	case p == "operations/op1" && r.Method == http.MethodGet:
		if s.pending > 0 {
			s.pending--
		}
		done()
	case p == "groups:lookup":
		for id, email := range s.groups {
			if email == r.URL.Query().Get("groupKey.id") && !s.blind {
				json.NewEncoder(w).Encode(map[string]string{"name": "groups/" + id})
				return
			}
		}
		denied()
	case len(parts) == 2 && parts[0] == "groups" && r.Method == http.MethodGet:
		email, ok := s.groups[parts[1]]
		switch {
		case s.blind:
			denied()
		case !ok:
			gerr(w, 404, "NOT_FOUND", "Requested entity was not found.", "")
		default:
			labels := map[string]string{"cloudidentity.googleapis.com/groups.discussion_forum": ""}
			if s.dynamic[parts[1]] {
				labels[dynamicLabel] = ""
			}
			json.NewEncoder(w).Encode(map[string]any{"name": "groups/" + parts[1], "groupKey": map[string]string{"id": email}, "displayName": "Group " + parts[1], "labels": labels})
		}
	case len(parts) == 3 && parts[2] == "memberships:lookup":
		email := r.URL.Query().Get("memberKey.id")
		_, ok := s.groups[parts[1]]
		switch {
		case s.blind:
			denied()
		case !ok:
			gerr(w, 404, "NOT_FOUND", "Requested entity was not found.", "")
		case !s.members[parts[1]][email]:
			if s.missCode == 403 {
				denied()
			} else {
				gerr(w, 404, "NOT_FOUND", "Requested entity was not found.", "")
			}
		default:
			json.NewEncoder(w).Encode(map[string]string{"name": "groups/" + parts[1] + "/memberships/" + memberID(email)})
		}
	case len(parts) == 3 && parts[2] == "memberships" && r.Method == http.MethodPost:
		var in struct {
			Key struct {
				ID string `json:"id"`
			} `json:"preferredMemberKey"`
			Roles []struct {
				Name string `json:"name"`
			} `json:"roles"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		_, ok := s.groups[parts[1]]
		switch {
		case s.blind || !ok:
			denied()
		case in.Key.ID == "" || len(in.Roles) != 1 || in.Roles[0].Name != "MEMBER":
			gerr(w, 400, "INVALID_ARGUMENT", "bad membership", "")
		case s.conflict || s.members[parts[1]][in.Key.ID]:
			gerr(w, 409, "ALREADY_EXISTS", "Member already exists.", "")
		default:
			if s.opError == "" {
				s.members[parts[1]][in.Key.ID] = true
			}
			done()
		}
	case len(parts) == 4 && parts[2] == "memberships" && r.Method == http.MethodDelete:
		found := false
		for email := range s.members[parts[1]] {
			if memberID(email) == parts[3] {
				delete(s.members[parts[1]], email)
				found = true
			}
		}
		if !found {
			gerr(w, 404, "NOT_FOUND", "Requested entity was not found.", "")
			return
		}
		done()
	default:
		gerr(w, 400, "INVALID_ARGUMENT", "unexpected call "+r.Method+" "+r.URL.Path, "")
	}
}

func (s *server) finish(w http.ResponseWriter) {
	if s.opError != "" {
		json.NewEncoder(w).Encode(map[string]any{"name": "operations/op1", "done": true, "error": map[string]any{"code": 7, "message": s.opError}})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"done": true, "response": map[string]string{"@type": "x"}})
}

// token checks the assertion the way Google does and hands out a token.
func (s *server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.tokenFail != "" {
		w.WriteHeader(400)
		fmt.Fprint(w, s.tokenFail)
		return
	}
	r.ParseForm()
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		s.t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
	}
	parts := strings.Split(r.Form.Get("assertion"), ".")
	if len(parts) != 3 {
		s.t.Errorf("assertion has %d parts", len(parts))
		w.WriteHeader(400)
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, d[:], sig); err != nil {
		s.t.Errorf("assertion signature: %v", err)
	}
	var hdr struct{ Alg, Typ, Kid string }
	var claims struct {
		Iss, Scope, Aud string
		Iat, Exp        int64
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(hb, &hdr)
	json.Unmarshal(cb, &claims)
	if hdr.Alg != "RS256" || hdr.Kid != "kid123" {
		s.t.Errorf("assertion header = %+v", hdr)
	}
	if claims.Iss != account || claims.Scope != scope || claims.Aud != s.ts.URL+"/token" || claims.Exp-claims.Iat != 3600 {
		s.t.Errorf("assertion claims = %+v", claims)
	}
	s.tokens++
	fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"Bearer","expires_in":3599}`, s.tokens)
}

var ctx = context.Background()

func TestTokenIsSignedCachedAndRenewedOnce(t *testing.T) {
	s, c := newServer(t)
	s.group("g0001", "eng@example.com", "ann@example.com")
	for range 3 {
		if ok, err := c.IsMember(ctx, "g0001", "ann@example.com"); err != nil || !ok {
			t.Fatalf("IsMember = %v, %v", ok, err)
		}
	}
	if s.tokens != 1 {
		t.Fatalf("fetched %d tokens for three calls, want 1", s.tokens)
	}
	// Google turns the token down once: jitd signs in again and repeats.
	s.reject = 1
	if ok, err := c.IsMember(ctx, "g0001", "ann@example.com"); err != nil || !ok {
		t.Fatalf("after a rejected token: %v, %v", ok, err)
	}
	if s.tokens != 2 {
		t.Fatalf("tokens = %d, want 2", s.tokens)
	}
	// It keeps turning it down: one more try, then the error.
	s.reject = 5
	if _, err := c.IsMember(ctx, "g0001", "ann@example.com"); status(err) != 401 {
		t.Fatalf("err = %v, want a 401", err)
	}
	if s.tokens != 3 {
		t.Fatalf("tokens = %d, want 3", s.tokens)
	}
}

func TestFindGroup(t *testing.T) {
	s, c := newServer(t)
	s.group("g0001", "eng@example.com")
	s.group("g0002", "all@example.com")
	s.dynamic["g0002"] = true

	g, err := c.FindGroup(ctx, " Eng@Example.com ")
	if err != nil || g.ID != "g0001" || g.Email != "eng@example.com" || g.Name != "Group g0001" || !g.Manageable() {
		t.Fatalf("by email: %+v, %v", g, err)
	}
	if g, err = c.FindGroup(ctx, "g0001"); err != nil || g.Email != "eng@example.com" {
		t.Fatalf("by ID: %+v, %v", g, err)
	}
	if g, err = c.FindGroup(ctx, "all@example.com"); err != nil || g.Manageable() {
		t.Fatalf("dynamic group: %+v, %v", g, err)
	}
	for _, ref := range []string{"nope@example.com", "g9999", "not an id"} {
		if _, err := c.FindGroup(ctx, ref); !errors.Is(err, ErrNotFound) {
			t.Errorf("FindGroup(%q) = %v, want ErrNotFound", ref, err)
		}
	}
	// Without the role every group is hidden, and that reads as not found.
	s.blind = true
	if _, err := c.FindGroup(ctx, "eng@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("without the role: %v", err)
	}
	// The API being off is not "no such group".
	s.blind, s.disabled = false, true
	if _, err := c.FindGroup(ctx, "eng@example.com"); !IsDisabled(err) {
		t.Fatalf("with the API off: %v", err)
	}
}

func TestIsMember(t *testing.T) {
	for _, miss := range []int{404, 403} {
		t.Run(fmt.Sprint("non-member answers ", miss), func(t *testing.T) {
			s, c := newServer(t)
			s.missCode = miss
			s.group("g0001", "eng@example.com", "ann@example.com")
			if ok, err := c.IsMember(ctx, "g0001", "Ann@Example.com"); err != nil || !ok {
				t.Fatalf("member: %v, %v", ok, err)
			}
			if ok, err := c.IsMember(ctx, "g0001", "bob@example.com"); err != nil || ok {
				t.Fatalf("non-member: %v, %v", ok, err)
			}
			// A group jitd cannot see is not "not a member".
			s.blind = true
			if ok, err := c.IsMember(ctx, "g0001", "ann@example.com"); err == nil || ok {
				t.Fatalf("hidden group: %v, %v", ok, err)
			}
			s.blind = false
			if _, err := c.IsMember(ctx, "g7777", "ann@example.com"); !errors.Is(err, errGroupGone) {
				t.Fatalf("deleted group: %v", err)
			}
		})
	}
}

func TestAddMember(t *testing.T) {
	s, c := newServer(t)
	s.group("g0001", "eng@example.com")
	if err := c.AddMember(ctx, "g0001", "Bob@Example.com"); err != nil {
		t.Fatal(err)
	}
	if !s.members["g0001"]["bob@example.com"] {
		t.Fatal("bob was not added under his lower-cased address")
	}
	// Again: Google says 409, the membership shows, so it is fine.
	if err := c.AddMember(ctx, "g0001", "bob@example.com"); err != nil {
		t.Fatalf("adding a member again: %v", err)
	}
	// A 409 with no membership to show for it is an error.
	s.conflict = true
	if err := c.AddMember(ctx, "g0001", "cat@example.com"); status(err) != 409 {
		t.Fatalf("unexplained 409: %v", err)
	}
	s.conflict = false

	// A change still running is waited for.
	s.pending = 2
	s.log()
	if err := c.AddMember(ctx, "g0001", "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.log(), ", "); got != "POST /v1/groups/g0001/memberships, GET /v1/operations/op1, GET /v1/operations/op1" {
		t.Fatalf("calls = %s", got)
	}
	// One that never finishes is an error, and not a refusal.
	s.pending = 1 << 30
	c.Wait = 20 * time.Millisecond
	err := c.AddMember(ctx, "g0001", "eve@example.com")
	if err == nil || IsRefusal(err) || !strings.Contains(err.Error(), "had not finished") {
		t.Fatalf("unfinished change: %v", err)
	}
	// One that fails is too.
	s.pending, s.opError = 0, "group is full"
	err = c.AddMember(ctx, "g0001", "fay@example.com")
	if err == nil || IsRefusal(err) || !strings.Contains(err.Error(), "group is full") {
		t.Fatalf("failed change: %v", err)
	}
	// Google refusing outright is a refusal.
	s.opError, s.blind = "", true
	if err := c.AddMember(ctx, "g0001", "gus@example.com"); !IsRefusal(err) {
		t.Fatalf("refused add: %v", err)
	}
}

func TestRemoveMember(t *testing.T) {
	for _, miss := range []int{404, 403} {
		t.Run(fmt.Sprint("non-member answers ", miss), func(t *testing.T) {
			s, c := newServer(t)
			s.missCode = miss
			s.group("g0001", "eng@example.com", "ann@example.com")
			if err := c.RemoveMember(ctx, "g0001", "ann@example.com"); err != nil {
				t.Fatal(err)
			}
			if s.members["g0001"]["ann@example.com"] {
				t.Fatal("ann is still a member")
			}
			// Not a member: nothing to delete.
			s.log()
			if err := c.RemoveMember(ctx, "g0001", "ann@example.com"); err != nil {
				t.Fatal(err)
			}
			for _, call := range s.log() {
				if strings.HasPrefix(call, "DELETE") {
					t.Fatalf("deleted a membership that was not there: %s", call)
				}
			}
			// The group was deleted: its memberships went with it.
			if err := c.RemoveMember(ctx, "g7777", "ann@example.com"); err != nil {
				t.Fatalf("deleted group: %v", err)
			}
			// ...but not while the credential does not work.
			s.disabled = true
			if err := c.RemoveMember(ctx, "g7777", "ann@example.com"); err == nil {
				t.Fatal("a deleted group was believed while the API is off")
			}
			s.disabled = false
			// A group jitd cannot see any more keeps its membership owed.
			s.group("g0002", "ops@example.com", "ann@example.com")
			s.blind = true
			if err := c.RemoveMember(ctx, "g0002", "ann@example.com"); err == nil {
				t.Fatal("removal from a hidden group reported as done")
			}
			if !s.members["g0002"]["ann@example.com"] {
				t.Fatal("test broken: ann should still be in g0002")
			}
		})
	}
}

func TestCheck(t *testing.T) {
	s, c := newServer(t)
	if err := c.Check(ctx); err != nil {
		t.Fatalf("working credential: %v", err)
	}
	// Check does not need the role.
	s.blind = true
	if err := c.Check(ctx); err != nil {
		t.Fatalf("without the role: %v", err)
	}
	s.disabled = true
	err := c.Check(ctx)
	if !IsDisabled(err) {
		t.Fatalf("API off: %v", err)
	}
	if what, fix := Explain(err, c.Key); !strings.Contains(what, "not enabled") || !strings.Contains(fix, "project=proj-1") {
		t.Fatalf("Explain = %q / %q", what, fix)
	}
	s.disabled, s.reject = false, 5
	if err := c.Check(ctx); status(err) != 401 {
		t.Fatalf("rejected token: %v", err)
	}

	s2, c2 := newServer(t)
	s2.tokenFail = `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`
	err = c2.Check(ctx)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "invalid_grant" {
		t.Fatalf("deleted key: %v", err)
	}
	if what, fix := Explain(err, c2.Key); !strings.Contains(what, "did not accept the key") || fix == "" {
		t.Fatalf("Explain = %q / %q", what, fix)
	}
}

func TestRetriesRateLimitsAndServerErrors(t *testing.T) {
	s, c := newServer(t)
	s.group("g0001", "eng@example.com", "ann@example.com")
	s.flaky = 2
	if ok, err := c.IsMember(ctx, "g0001", "ann@example.com"); err != nil || !ok {
		t.Fatalf("after two 503s: %v, %v", ok, err)
	}
	s.flaky = 3
	if _, err := c.IsMember(ctx, "g0001", "ann@example.com"); status(err) != 503 || IsRefusal(err) {
		t.Fatalf("after three 503s: %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	s, c := newServer(t)
	s.group("g0001", "eng@example.com")
	if err := c.Check(ctx); err != nil { // sign in while the server is up
		t.Fatal(err)
	}
	s.ts.Close()
	_, err := c.IsMember(ctx, "g0001", "ann@example.com")
	if err == nil || IsRefusal(err) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "ann@example.com") {
		t.Fatalf("the error names the member: %v", err)
	}
	if what, _ := Explain(err, c.Key); !strings.Contains(what, "could not reach Google") {
		t.Fatalf("Explain = %q", what)
	}
}

func TestParseKey(t *testing.T) {
	k, err := ParseKey(keyJSON(t, nil))
	if err != nil || k.Email != account || k.ID != "kid123" || k.Project != "proj-1" {
		t.Fatalf("%+v, %v", k, err)
	}
	pk1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey(t))}))
	if _, err := ParseKey(keyJSON(t, map[string]string{"private_key": pk1})); err != nil {
		t.Fatalf("PKCS#1 key: %v", err)
	}
	for name, text := range map[string]string{
		"empty":         "  ",
		"not JSON":      "-----BEGIN PRIVATE KEY-----",
		"no type":       `{"client_email":"a@b"}`,
		"user":          keyJSON(t, map[string]string{"type": "authorized_user"}),
		"no email":      keyJSON(t, map[string]string{"client_email": ""}),
		"no key":        keyJSON(t, map[string]string{"private_key": ""}),
		"key not PEM":   keyJSON(t, map[string]string{"private_key": "SECRETSECRET"}),
		"key not a key": keyJSON(t, map[string]string{"private_key": "-----BEGIN PRIVATE KEY-----\nU0VDUkVUU0VDUkVU\n-----END PRIVATE KEY-----\n"}),
	} {
		_, err := ParseKey(text)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "U0VDUkVU") {
			t.Errorf("%s: the error quotes the key: %v", name, err)
		}
	}
}

// A key file names a token endpoint. jitd must not go there.
func TestKeyCannotMoveTheTokenEndpoint(t *testing.T) {
	c, err := NewFromValues(map[string]string{EnvKey: keyJSON(t, map[string]string{"token_uri": "https://evil.example/token"})})
	if err != nil {
		t.Fatal(err)
	}
	if c.TokenURL != "https://oauth2.googleapis.com/token" || c.BaseURL != "https://cloudidentity.googleapis.com" {
		t.Fatalf("token endpoint %q, API %q", c.TokenURL, c.BaseURL)
	}
	if _, err := NewFromValues(map[string]string{}); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("no key: %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hit bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer ts.Close()
	k, _ := ParseKey(keyJSON(t, nil))
	c := &HTTP{Key: k, BaseURL: ts.URL, TokenURL: ts.URL + "/token", Backoff: time.Millisecond}
	if err := c.Check(ctx); err == nil {
		t.Fatal("a redirect was taken for an answer")
	}
	if hit {
		t.Fatal("jitd followed a redirect with its assertion")
	}
}

func TestDynamic(t *testing.T) {
	vars := map[string]string{}
	var loadErr error
	built := 0
	fake := NewFake()
	fake.AddGroup("g0001", "eng@example.com", false)
	d := &Dynamic{
		Load: func() (map[string]string, error) { return vars, loadErr },
		New: func(map[string]string) (Client, error) {
			built++
			return fake, nil
		},
	}
	if d.Enabled() || !errors.Is(d.Err(), ErrUnconfigured) {
		t.Fatalf("no key: enabled %v, %v", d.Enabled(), d.Err())
	}
	if _, err := d.FindGroup(ctx, "eng@example.com"); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("FindGroup without a key: %v", err)
	}
	vars = map[string]string{EnvKey: "key one"}
	if g, err := d.FindGroup(ctx, "eng@example.com"); err != nil || g.ID != "g0001" {
		t.Fatalf("%+v, %v", g, err)
	}
	d.Check(ctx)
	if built != 1 {
		t.Fatalf("built %d clients for one key", built)
	}
	// A new key is noticed.
	vars = map[string]string{EnvKey: "key two"}
	d.Check(ctx)
	if built != 2 {
		t.Fatalf("built = %d after the key changed, want 2", built)
	}
	// Settings that cannot be read: carry on with the last ones.
	loadErr = errors.New("bad line 3")
	if err := d.AddMember(ctx, "g0001", "ann@example.com"); err != nil || !fake.Member("g0001", "ann@example.com") {
		t.Fatalf("with unreadable settings: %v", err)
	}
	if d.StaleSettings() != "bad line 3" || built != 2 {
		t.Fatalf("stale = %q, built = %d", d.StaleSettings(), built)
	}
	// A key that cannot be parsed switches Google off, with the reason.
	loadErr = nil
	d.New = nil
	vars = map[string]string{EnvKey: "{}"}
	if d.Enabled() || d.Err() == nil || errors.Is(d.Err(), ErrUnconfigured) {
		t.Fatalf("bad key: %v", d.Err())
	}
}

func TestFake(t *testing.T) {
	f := NewFake()
	f.AddGroup("g0001", "Eng@example.com", false)
	if g, err := f.FindGroup(ctx, "eng@example.com"); err != nil || g.ID != "g0001" {
		t.Fatalf("%+v, %v", g, err)
	}
	if _, err := f.FindGroup(ctx, "x@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	f.AddMember(ctx, "g0001", "Ann@example.com")
	if ok, _ := f.IsMember(ctx, "g0001", "ann@example.com"); !ok {
		t.Fatal("ann is not a member")
	}
	f.Fail["remove:g0001"] = errors.New("boom")
	if err := f.RemoveMember(ctx, "g0001", "ann@example.com"); err == nil {
		t.Fatal("remove did not fail")
	}
	if got := strings.Join(f.Mutations(), ", "); got != "ADD g0001 Ann@example.com, REMOVE g0001 ann@example.com" {
		t.Fatalf("mutations = %s", got)
	}
}
