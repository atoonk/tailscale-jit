package jithttp

import (
	"strings"
	"testing"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

// The flow form shows what an approval grants as actions: only the ones a
// flow has are open, the rest are offered to add, and an integration that
// is not connected is offered as a link to its page.
func TestFlowFormShowsOnlyWhatAFlowGrants(t *testing.T) {
	srv, _, _ := newGoogleServer(t, nil)
	const (
		choose    = `class="card fields grants empty"`
		tsClosed  = `data-action="tailscale" hidden`
		gClosed   = `data-action="google" hidden`
		gSection  = `data-action="google"`
		addGoogle = `data-add="google"`
		connect   = `Not connected · <a href="/admin/integrations/google">Connect Google</a>`
	)
	check := func(what, path string, want, not []string) {
		t.Helper()
		code, body := getPage(t, srv, "root", path)
		if code != 200 {
			t.Fatalf("%s: %s = %d", what, path, code)
		}
		for _, s := range want {
			if !strings.Contains(body, s) {
				t.Errorf("%s: the form lacks %q", what, s)
			}
		}
		for _, s := range not {
			if strings.Contains(body, s) {
				t.Errorf("%s: the form has %q", what, s)
			}
		}
	}

	// Only Tailscale can be granted, so there is nothing to choose.
	check("nothing connected", "/admin/workflows/new",
		[]string{`data-action="tailscale"`, `data-add="tailscale"`, connect},
		[]string{choose, tsClosed, gSection, addGoogle})

	key := google.FakeKey(googleAccount, "acme-prod")
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"key": key, "allowed_domains": "example.com", "grant_allowlist": "*"}, nil); code != 200 {
		t.Fatalf("saving = %d", code)
	}
	check("Google connected", "/admin/workflows/new",
		[]string{choose, tsClosed, gClosed, addGoogle},
		[]string{connect})

	var groups, device jit.Workflow
	people := map[string]any{"requesters": []string{"autogroup:member"}, "approvers": []string{"bob@example.com"}, "max_duration": "1h"}
	create := func(out *jit.Workflow, fields map[string]any) {
		t.Helper()
		for k, v := range people {
			fields[k] = v
		}
		if code := call(t, srv, "root", "POST", "/v1/workflows", fields, out); code != 201 {
			t.Fatalf("creating %v = %d", fields["name"], code)
		}
	}
	create(&groups, map[string]any{"name": "AWS admin", "google_groups": []map[string]string{{"name": googleAdminsA}}})
	create(&device, map[string]any{"name": "Databases", "attribute": "db_ro"})

	check("a flow with Google groups only", "/admin/workflows/"+groups.ID,
		[]string{tsClosed, gSection, googleAdminsA, `data-add="tailscale"`},
		[]string{choose, gClosed})
	check("a flow with a posture attribute only", "/admin/workflows/"+device.ID,
		[]string{`value="db_ro"`, gClosed, addGoogle},
		[]string{choose, tsClosed})
}
