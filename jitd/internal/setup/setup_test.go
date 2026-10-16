package setup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

type fakeTS struct {
	policyErr, readErr, writeErr error
	set, deleted                 []string
}

func (f *fakeTS) SetAttribute(_ context.Context, dev, key string, _ any, _ time.Time, _ string) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.set = append(f.set, dev+"|"+key)
	return nil
}
func (f *fakeTS) GetAttributes(context.Context, string) (tsapi.Attributes, error) {
	return tsapi.Attributes{Attributes: map[string]any{"custom:x": true, "node:os": "linux"}}, f.readErr
}
func (f *fakeTS) DeleteAttribute(_ context.Context, dev, key string) error {
	f.deleted = append(f.deleted, dev+"|"+key)
	return nil
}
func (f *fakeTS) GetPolicy(context.Context) (tsapi.Policy, error) {
	return tsapi.Policy{Groups: map[string][]string{"group:sre": {"a@x"}}}, f.policyErr
}

func TestReadEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "env")
	os.WriteFile(p, []byte("# comment\n\nexport TS_API_KEY=\"tskey-api-1\"\nTS_OAUTH_CLIENT_ID = 'abc'\n"), 0o600)
	got, err := ReadEnvFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got["TS_API_KEY"] != "tskey-api-1" || got["TS_OAUTH_CLIENT_ID"] != "abc" {
		t.Errorf("got %v", got)
	}
	os.WriteFile(p, []byte("just words\n"), 0o600)
	if _, err := ReadEnvFile(p); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("bad line: err=%v", err)
	}
	if _, err := ReadEnvFile(filepath.Join(t.TempDir(), "nope")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: err=%v", err)
	}
}

func newChecker(t *testing.T, ts *fakeTS, env string) (*Checker, *tsapi.Switchable) {
	t.Helper()
	for _, k := range tsapi.CredentialVars {
		t.Setenv(k, "")
	}
	p := filepath.Join(t.TempDir(), "env")
	if env != "" {
		os.WriteFile(p, []byte(env), 0o600)
	}
	target := &tsapi.Switchable{}
	c := &Checker{
		EnvFile: p, Tag: "tag:jit", Target: target,
		Node:      func(context.Context) (Node, error) { return Node{ID: "nJIT", Tags: []string{"tag:jit"}}, nil },
		NewClient: func(context.Context, string, map[string]string) (tsapi.Client, error) { return ts, nil },
	}
	return c, target
}

func byName(r *Result, name string) Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{Name: "missing " + name}
}

func TestRunAllGood(t *testing.T) {
	ts := &fakeTS{}
	c, target := newChecker(t, ts, "TS_OAUTH_CLIENT_ID=id\nTS_OAUTH_CLIENT_SECRET=s\n")
	res := c.Run(context.Background())
	if !res.OK {
		t.Fatalf("want ok, got %+v", res.Checks)
	}
	if res.Credentials.Kind != "oauth" || strings.Join(res.Credentials.FromFile, ",") != "TS_OAUTH_CLIENT_ID,TS_OAUTH_CLIENT_SECRET" {
		t.Errorf("credentials: %+v", res.Credentials)
	}
	// The write check sets and removes a throwaway attribute on the node itself.
	if len(ts.set) != 1 || ts.set[0] != "nJIT|"+selfCheckKey || len(ts.deleted) != 1 {
		t.Errorf("set=%v deleted=%v", ts.set, ts.deleted)
	}
	if _, err := target.GetPolicy(context.Background()); err != nil {
		t.Errorf("target not switched: %v", err)
	}
	if c.Last() != res {
		t.Error("Last() should return the result")
	}
}

func TestRunNoCredentials(t *testing.T) {
	c, target := newChecker(t, &fakeTS{}, "")
	res := c.Run(context.Background())
	if res.OK {
		t.Fatal("want failure")
	}
	cr := byName(res, "Credentials")
	if cr.OK || !strings.Contains(cr.Detail, "does not exist") || !strings.Contains(cr.Fix, c.EnvFile) {
		t.Errorf("credentials check: %+v", cr)
	}
	if w := byName(res, "Posture attributes write"); !w.Skipped {
		t.Errorf("write should be skipped: %+v", w)
	}
	if _, err := target.GetPolicy(context.Background()); !errors.Is(err, tsapi.ErrUnconfigured) {
		t.Errorf("target should be unconfigured, got %v", err)
	}
}

func TestRunMissingWriteScope(t *testing.T) {
	ts := &fakeTS{writeErr: &tsapi.APIError{Method: "POST", Path: "/x", Status: http.StatusForbidden, Body: "forbidden"}}
	c, target := newChecker(t, ts, "TS_API_KEY=tskey-api-x\n")
	res := c.Run(context.Background())
	if res.OK {
		t.Fatal("want failure")
	}
	w := byName(res, "Posture attributes write")
	if w.OK || !strings.Contains(w.Fix, "devices:posture_attributes (write)") {
		t.Errorf("write check: %+v", w)
	}
	if cr := byName(res, "Credentials"); !cr.OK || !strings.Contains(cr.Fix, "90 days") {
		t.Errorf("api key should pass with an expiry warning: %+v", cr)
	}
	// Reads work, so the client stays in use (group lookups, admin access).
	if _, err := target.GetPolicy(context.Background()); err != nil {
		t.Errorf("a client that can still read should stay in use, got %v", err)
	}
}

func TestRunWrongTagStillServes(t *testing.T) {
	c, target := newChecker(t, &fakeTS{}, "TS_API_KEY=k\n")
	c.Node = func(context.Context) (Node, error) { return Node{ID: "nJIT", Tags: []string{"tag:other"}}, nil }
	res := c.Run(context.Background())
	if res.OK {
		t.Fatal("want failure on the tag")
	}
	if tg := byName(res, "Node tag"); tg.OK || !strings.Contains(tg.Detail, "tag:other") {
		t.Errorf("tag check: %+v", tg)
	}
	if _, err := target.GetPolicy(context.Background()); err != nil {
		t.Errorf("credentials work, so the client should be in use: %v", err)
	}
}

func TestEnvironmentFillsIn(t *testing.T) {
	c, _ := newChecker(t, &fakeTS{}, "TS_OAUTH_CLIENT_ID=id\n")
	t.Setenv("TS_OAUTH_CLIENT_SECRET", "s")
	res := c.Run(context.Background())
	if !res.OK || strings.Join(res.Credentials.FromEnv, ",") != "TS_OAUTH_CLIENT_SECRET" {
		t.Errorf("got ok=%v creds=%+v", res.OK, res.Credentials)
	}
}

// A network failure says nothing about the credential: keep it in use.
func TestRunTransientKeepsClient(t *testing.T) {
	ts := &fakeTS{policyErr: errors.New("dial tcp: i/o timeout")}
	c, target := newChecker(t, ts, "TS_API_KEY=k\n")
	res := c.Run(context.Background())
	if res.OK || !res.Transient {
		t.Fatalf("want a transient failure, got ok=%v transient=%v", res.OK, res.Transient)
	}
	ts.policyErr = nil
	if _, err := target.GetPolicy(context.Background()); err != nil {
		t.Errorf("client should stay in use after a transient failure: %v", err)
	}
	// A 401 is definite: the client is dropped.
	ts.policyErr = &tsapi.APIError{Method: "GET", Path: "/x", Status: http.StatusUnauthorized}
	if res := c.Run(context.Background()); res.Transient {
		t.Error("401 is not transient")
	}
	if _, err := target.GetPolicy(context.Background()); !errors.Is(err, tsapi.ErrUnconfigured) {
		t.Errorf("client should be dropped after a 401, got %v", err)
	}
}

// A 5xx from the OAuth token endpoint is an outage, not a bad secret.
func TestTokenEndpointOutageIsTransient(t *testing.T) {
	outage := &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusServiceUnavailable}}
	if credentialRejected(fmt.Errorf("tailscale API GET /x: %w", outage)) {
		t.Error("503 from the token endpoint treated as a rejected credential")
	}
	bad := &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusUnauthorized}, ErrorCode: "invalid_client"}
	if !credentialRejected(fmt.Errorf("tailscale API GET /x: %w", bad)) {
		t.Error("invalid_client not treated as rejected")
	}
}

func TestReadableEnvFileWarns(t *testing.T) {
	c, _ := newChecker(t, &fakeTS{}, "TS_API_KEY=k\n")
	if res := c.Run(context.Background()); res.Credentials.FileWarning != "" {
		t.Errorf("0600 file warned: %q", res.Credentials.FileWarning)
	}
	os.Chmod(c.EnvFile, 0o644)
	if res := c.Run(context.Background()); !strings.Contains(res.Credentials.FileWarning, "chmod 600") {
		t.Errorf("0644 file: warning %q", res.Credentials.FileWarning)
	}
}
