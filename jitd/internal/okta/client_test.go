package okta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeOrg is a tiny Okta org over HTTP.
type fakeOrg struct {
	mu      sync.Mutex
	members map[string]bool // group|user
	calls   []string
	auth    []string
}

func newOrg(t *testing.T) (*fakeOrg, *HTTP) {
	o := &fakeOrg{members: map[string]bool{}}
	srv := httptest.NewServer(o)
	t.Cleanup(srv.Close)
	c, err := NewFromValues(map[string]string{"OKTA_ORG_URL": srv.URL + "/", "OKTA_API_TOKEN": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	return o, c
}

func (o *fakeOrg) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, r.Method+" "+r.URL.RequestURI())
	o.auth = append(o.auth, r.Header.Get("Authorization"))
	notFound := func() {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found"}`)
	}
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/api/v1/users/alice@example.com":
		fmt.Fprint(w, `{"id":"00uA","status":"ACTIVE","profile":{"login":"alice@example.com","email":"alice@example.com"}}`)
	case r.Method == "GET" && strings.HasPrefix(p, "/api/v1/users/") && !strings.HasSuffix(p, "/groups"):
		notFound()
	case r.Method == "GET" && p == "/api/v1/users":
		if r.URL.Query().Get("search") == `profile.email eq "bob@corp.example"` {
			fmt.Fprint(w, `[{"id":"00uB","status":"ACTIVE","profile":{"login":"bob","email":"bob@corp.example"}}]`)
			return
		}
		fmt.Fprint(w, `[]`)
	case r.Method == "GET" && p == "/api/v1/groups":
		// q is a prefix match: return near misses too.
		fmt.Fprint(w, `[{"id":"00gAAAAAAAAAAAA1","type":"OKTA_GROUP","profile":{"name":"AWS-Admin"}},{"id":"00gAAAAAAAAAAAA2","type":"OKTA_GROUP","profile":{"name":"AWS-Admin-Old"}}]`)
	case r.Method == "GET" && p == "/api/v1/groups/00gAAAAAAAAAAAA1":
		fmt.Fprint(w, `{"id":"00gAAAAAAAAAAAA1","type":"OKTA_GROUP","profile":{"name":"AWS-Admin"}}`)
	case r.Method == "GET" && strings.HasPrefix(p, "/api/v1/groups/"):
		notFound()
	case r.Method == "GET" && p == "/api/v1/users/00uA/groups":
		// Two pages.
		if r.URL.Query().Get("after") == "" {
			w.Header().Add("Link", `<http://`+r.Host+`/api/v1/users/00uA/groups?limit=1>; rel="self"`)
			w.Header().Add("Link", `<http://`+r.Host+`/api/v1/users/00uA/groups?after=x&limit=1>; rel="next"`)
			fmt.Fprint(w, `[{"id":"00gEVERYONE"}]`)
			return
		}
		var out []string
		for k := range o.members {
			if g, u, _ := strings.Cut(k, "|"); u == "00uA" {
				out = append(out, `{"id":"`+g+`"}`)
			}
		}
		fmt.Fprint(w, "["+strings.Join(out, ",")+"]")
	case strings.HasPrefix(p, "/api/v1/groups/") && strings.Contains(p, "/users/"):
		parts := strings.Split(p, "/") // "", api, v1, groups, G, users, U
		k := parts[4] + "|" + parts[6]
		switch r.Method {
		case "PUT":
			o.members[k] = true
		case "DELETE":
			if !o.members[k] {
				notFound()
				return
			}
			delete(o.members, k)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusTeapot)
	}
}

func TestHTTPClient(t *testing.T) {
	ctx := context.Background()
	o, c := newOrg(t)

	u, err := c.FindUser(ctx, "alice@example.com")
	if err != nil || u.ID != "00uA" {
		t.Fatalf("FindUser by login = %+v, %v", u, err)
	}
	u, err = c.FindUser(ctx, "bob@corp.example")
	if err != nil || u.ID != "00uB" {
		t.Fatalf("FindUser by email = %+v, %v", u, err)
	}
	if _, err := c.FindUser(ctx, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindUser unknown: %v", err)
	}

	g, err := c.FindGroup(ctx, "AWS-Admin")
	if err != nil || g.ID != "00gAAAAAAAAAAAA1" || !g.Manageable() {
		t.Fatalf("FindGroup by name = %+v, %v", g, err)
	}
	if g, err := c.FindGroup(ctx, "00gAAAAAAAAAAAA1"); err != nil || g.Name() != "AWS-Admin" {
		t.Fatalf("FindGroup by id = %+v, %v", g, err)
	}
	if _, err := c.FindGroup(ctx, "AWS"); !errors.Is(err, ErrNotFound) {
		t.Errorf("prefix match was accepted: %v", err)
	}
	if _, err := c.FindGroup(ctx, "00gMISSINGMISSING"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindGroup unknown id: %v", err)
	}

	gid := "00gAAAAAAAAAAAA1"
	if m, err := c.IsMember(ctx, gid, "00uA"); err != nil || m {
		t.Fatalf("IsMember before = %v, %v", m, err)
	}
	if err := c.AddMember(ctx, gid, "00uA"); err != nil {
		t.Fatal(err)
	}
	if m, err := c.IsMember(ctx, gid, "00uA"); err != nil || !m {
		t.Fatalf("IsMember after add (second page) = %v, %v", m, err)
	}
	if err := c.RemoveMember(ctx, gid, "00uA"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveMember(ctx, gid, "00uA"); err != nil {
		t.Errorf("removing a non-member should be a no-op: %v", err)
	}

	for _, a := range o.auth {
		if a != "SSWS tok" {
			t.Fatalf("Authorization = %q", a)
		}
	}
}

func TestAPIErrorHidesQuery(t *testing.T) {
	_, c := newOrg(t)
	err := c.do(context.Background(), "GET", "/nope?search=secret@example.com", nil, nil, nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusTeapot || strings.Contains(err.Error(), "secret") {
		t.Errorf("err = %v", err)
	}
}

func TestNewFromValues(t *testing.T) {
	for _, tc := range []struct {
		vars map[string]string
		ok   bool
	}{
		{map[string]string{}, false},
		{map[string]string{"OKTA_ORG_URL": "https://x.okta.com"}, false},
		{map[string]string{"OKTA_ORG_URL": "https://x.okta.com", "OKTA_API_TOKEN": "t"}, true},
		{map[string]string{"OKTA_ORG_URL": "http://x.okta.com", "OKTA_API_TOKEN": "t"}, false},
		{map[string]string{"OKTA_ORG_URL": "x.okta.com", "OKTA_API_TOKEN": "t"}, false},
	} {
		_, err := NewFromValues(tc.vars)
		if (err == nil) != tc.ok {
			t.Errorf("%v: err = %v", tc.vars, err)
		}
	}
}

func TestDynamicReloads(t *testing.T) {
	vars := map[string]string{}
	d := &Dynamic{Load: func() map[string]string { return vars }}
	if d.Enabled() {
		t.Fatal("enabled without credentials")
	}
	if _, err := d.FindUser(context.Background(), "a"); !errors.Is(err, ErrUnconfigured) {
		t.Errorf("err = %v", err)
	}
	vars = map[string]string{"OKTA_ORG_URL": "https://x.okta.com", "OKTA_API_TOKEN": "t"}
	if !d.Enabled() {
		t.Error("not enabled after credentials appeared")
	}
}
