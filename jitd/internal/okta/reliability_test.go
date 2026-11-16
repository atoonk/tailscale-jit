package okta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func clientFor(t *testing.T, h http.HandlerFunc) *HTTP {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewFromValues(map[string]string{"OKTA_ORG_URL": srv.URL, "OKTA_API_TOKEN": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A 200 whose body is cut off must not read as an empty list.
func TestUserGroupsTruncatedBody(t *testing.T) {
	c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	})
	if gs, err := c.UserGroups(context.Background(), "00uA"); err == nil {
		t.Errorf("a cut-off response read as %d groups and no error", len(gs))
	}
	if m, err := c.IsMember(context.Background(), "00gAAAAAAAAAAAA1", "00uA"); err == nil {
		t.Errorf("a cut-off response read as member=%v and no error", m)
	}
}

// A 200 with no body at all is not an empty list either.
func TestUserGroupsEmptyBody(t *testing.T) {
	c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {})
	if gs, err := c.UserGroups(context.Background(), "00uA"); err == nil {
		t.Errorf("an empty response read as %d groups and no error", len(gs))
	}
}

// A next link the client will not follow is an error, not the end of the list.
func TestUserGroupsNextLink(t *testing.T) {
	one := `[{"id":"00gAAAAAAAAAAAA1","type":"OKTA_GROUP","profile":{"name":"one"}}]`
	foreign := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<https://ACME.okta.com/api/v1/users/00uA/groups?after=x>; rel="next"`)
		fmt.Fprint(w, one)
	})
	if gs, err := foreign.UserGroups(context.Background(), "00uA"); err == nil {
		t.Errorf("%d groups and no error although the next page was not followed", len(gs))
	}
	// The same host written in another case is the same host.
	var c *HTTP
	c = clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			w.Header().Add("Link", `<`+strings.Replace(c.BaseURL, "http://", "HTTP://", 1)+`/api/v1/users/00uA/groups?after=x>; rel="next"`)
			w.Header().Add("Link", `<`+c.BaseURL+`/api/v1/users/00uA/groups>; rel="self"`)
			fmt.Fprint(w, one)
			return
		}
		fmt.Fprint(w, `[{"id":"00gAAAAAAAAAAAA2","type":"OKTA_GROUP","profile":{"name":"two"}}]`)
	})
	gs, err := c.UserGroups(context.Background(), "00uA")
	if err != nil || len(gs) != 2 {
		t.Errorf("got %d groups, err %v; want both pages", len(gs), err)
	}
}

// A 404 on removal counts as removed only when Okta confirms it another way.
func TestRemoveMemberNotFound(t *testing.T) {
	const notFound = `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found"}`
	for _, tc := range []struct {
		name       string
		userGroups string // body of GET /users/00uA/groups; "" answers 404
		check      int    // status of GET /groups?limit=1
		removed    bool
	}{
		{"user exists and is not in the group", `[{"id":"00gOTHER000000001"}]`, 200, true},
		{"user is still listed in the group", `[{"id":"00gAAAAAAAAAAAA1"}]`, 200, false},
		{"user is gone and the API works", "", 200, true},
		{"nothing is found at this URL", "", 404, false},
		{"user is gone and the credential is refused", "", 401, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "GET" && r.URL.Path == "/api/v1/users/00uA/groups" && tc.userGroups != "":
					fmt.Fprint(w, tc.userGroups)
				case r.Method == "GET" && r.URL.Path == "/api/v1/groups" && tc.check == 200:
					fmt.Fprint(w, `[]`)
				case r.Method == "GET" && r.URL.Path == "/api/v1/groups":
					w.WriteHeader(tc.check)
					fmt.Fprint(w, notFound)
				default:
					w.WriteHeader(404)
					fmt.Fprint(w, notFound)
				}
			})
			err := c.RemoveMember(context.Background(), "00gAAAAAAAAAAAA1", "00uA")
			if (err == nil) != tc.removed {
				t.Errorf("err = %v, want removed = %v", err, tc.removed)
			}
		})
	}
}

// While the env file cannot be read, the client keeps the settings it had.
func TestDynamicKeepsSettingsOnLoadError(t *testing.T) {
	vars := map[string]string{"OKTA_ORG_URL": "https://a.okta.com", "OKTA_API_TOKEN": "t1"}
	var lerr error
	var reported []error
	d := &Dynamic{
		Load:        func() (map[string]string, error) { return vars, lerr },
		OnLoadError: func(err error) { reported = append(reported, err) },
	}
	lerr = errors.New("env line 3: expected KEY=VALUE")
	if d.Enabled() {
		t.Fatal("enabled although the settings were never read")
	}
	if err := d.Err(); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("Err = %v, want the read error", err)
	}
	lerr = nil
	if !d.Enabled() {
		t.Fatal("not enabled with good settings")
	}
	lerr, vars = errors.New("permission denied"), nil
	for i := 0; i < 3; i++ {
		if !d.Enabled() {
			t.Fatal("a failed read switched Okta off")
		}
	}
	lerr, vars = nil, map[string]string{}
	if d.Enabled() || !errors.Is(d.Err(), ErrUnconfigured) {
		t.Errorf("settings without credentials: Err = %v, want ErrUnconfigured", d.Err())
	}
	// first failure, recovery, second failure, recovery: each reported once
	if len(reported) != 4 || reported[0] == nil || reported[1] != nil || reported[2] == nil || reported[3] != nil {
		t.Errorf("load errors reported: %v", reported)
	}
}

// Okta's API does not redirect. Following one would post the signed client
// assertion, good for five minutes, to wherever the answer points.
func TestTokenRequestDoesNotFollowRedirects(t *testing.T) {
	var got string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got = r.PostForm.Get("client_assertion")
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer other.Close()
	org := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer org.Close()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewFromValues(map[string]string{"OKTA_ORG_URL": org.URL, "OKTA_CLIENT_ID": "0oaTEST", "OKTA_PRIVATE_KEY": rsaPEM(t, k, false)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err == nil {
		t.Error("a redirected token request counted as a working credential")
	}
	if got != "" {
		t.Error("the signed client assertion was posted to another host after a redirect")
	}
}
