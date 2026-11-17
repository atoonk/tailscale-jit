package jithttp

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/google"
	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

// jsonNames is the JSON name of every field of the struct type t.
func jsonNames(t reflect.Type) map[string]bool {
	names := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		names[name] = true
	}
	return names
}

// The API's layout of a flow is written out by hand beside jit.Workflow.
// A field added to the flow has to be added there as well, or the API
// would drop it without a word, on the way in and on the way out.
func TestFlowJSONCoversWorkflow(t *testing.T) {
	api := jsonNames(reflect.TypeOf(flowJSON{}))
	for name := range jsonNames(reflect.TypeOf(jit.Workflow{})) {
		if !api[name] {
			t.Errorf("jit.Workflow has %q and flowJSON does not", name)
		}
	}

	at := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	full := jit.Workflow{
		ID: "wf_1", Name: "On-call", Description: "everything for an incident",
		Attribute:    "custom:jit_oncall",
		OktaGroups:   []jit.GroupRef{{ID: "00g1", Name: "AWS-Prod-Admin"}},
		GoogleGroups: []jit.GroupRef{{ID: "01g", Name: "viewers@example.com"}},
		Resources:    []jit.Resource{{Name: "tag:prod", Description: "production"}},
		Requesters:   []jit.Principal{"group:sre"}, Approvers: []jit.Principal{"bob@example.com"},
		AllowSelfApproval: true, AutoApprove: true, AutoApproveBy: "root@example.com", AutoApproveAt: &at,
		UpdatedBy: "root@example.com", MaxDuration: jit.Duration(4 * time.Hour), ApprovalTimeout: jit.Duration(2 * time.Hour),
		ApprovalsRequired: 2, DefaultDuration: jit.Duration(time.Hour), Disabled: true,
		Slack:     &jit.WorkflowSlack{Channel: "C1", ChannelName: "access", DMApprovers: true, BrowserOnly: true},
		CreatedAt: at, UpdatedAt: at.Add(time.Minute),
	}
	// Every field is set, so that one the conversion forgets shows below.
	for v, i := reflect.ValueOf(full), 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Fatalf("this test leaves jit.Workflow.%s empty; set it above", v.Type().Field(i).Name)
		}
	}
	b, err := json.Marshal(flowOut(&full))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{"attribute", "okta_groups", "google_groups"} {
		if _, has := top[old]; has {
			t.Errorf("the API's flow still has %q at the top:\n%s", old, b)
		}
	}
	for _, name := range []string{"grants", "resources"} {
		if _, has := top[name]; !has {
			t.Errorf("the API's flow has no %s:\n%s", name, b)
		}
	}
	var back flowJSON
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	got, err := back.workflow()
	if err != nil {
		t.Fatal(err)
	}
	for g, w, i := reflect.ValueOf(got), reflect.ValueOf(full), 0; i < w.NumField(); i++ {
		if !reflect.DeepEqual(g.Field(i).Interface(), w.Field(i).Interface()) {
			t.Errorf("jit.Workflow.%s changed on its way through the API's layout (see flowOut and flowJSON.workflow):\n got %+v\nwant %+v",
				w.Type().Field(i).Name, g.Field(i).Interface(), w.Field(i).Interface())
		}
	}
}

// What an approval grants is under "grants" in everything /v1/workflows
// answers, whichever layout the flow was written in, and what the flow
// gives access to is beside it; a flow read from the API can be sent
// straight back; and a body in both layouts is refused.
func TestFlowAPIGrants(t *testing.T) {
	srv, _, _ := newGoogleServer(t, nil)
	key := google.FakeKey(googleAccount, "acme-prod")
	if code := call(t, srv, "root", "PUT", "/v1/google", map[string]any{"key": key, "allowed_domains": "example.com", "grant_allowlist": "*"}, nil); code != 200 {
		t.Fatalf("connecting Google = %d", code)
	}
	type flow struct {
		ID     string `json:"id"`
		Grants struct {
			Tailscale *struct {
				Attribute string `json:"attribute"`
			} `json:"tailscale"`
			Okta   *struct{} `json:"okta"`
			Google *struct {
				Groups []jit.GroupRef `json:"groups"`
			} `json:"google"`
		} `json:"grants"`
		Resources []jit.Resource `json:"resources"`
		// Gone from the top level.
		Attribute    *string         `json:"attribute"`
		GoogleGroups json.RawMessage `json:"google_groups"`
	}
	check := func(what string, f flow, attribute string, google bool, resources ...string) {
		t.Helper()
		if f.Attribute != nil || f.GoogleGroups != nil {
			t.Errorf("%s: the answer has the older top-level fields: %+v", what, f)
		}
		switch ts := f.Grants.Tailscale; {
		case attribute == "" && ts != nil:
			t.Errorf("%s: grants.tailscale = %+v, want none", what, ts)
		case attribute != "" && (ts == nil || ts.Attribute != attribute):
			t.Errorf("%s: grants.tailscale = %+v, want attribute %q", what, ts, attribute)
		}
		var names []string
		for _, r := range f.Resources {
			names = append(names, r.Name)
		}
		// A list even when it is empty, never null.
		if f.Resources == nil || !slices.Equal(names, resources) {
			t.Errorf("%s: resources = %v, want the list %v", what, f.Resources, resources)
		}
		switch g := f.Grants.Google; {
		case !google && g != nil:
			t.Errorf("%s: grants.google = %+v, want none", what, g)
		case google && (g == nil || len(g.Groups) != 1 || g.Groups[0].Name != googleAdminsA || g.Groups[0].ID == ""):
			t.Errorf("%s: grants.google = %+v, want %s with its ID", what, g, googleAdminsA)
		}
		if f.Grants.Okta != nil {
			t.Errorf("%s: grants.okta is there for a flow with no Okta groups", what)
		}
	}
	people := func(fields map[string]any) map[string]any {
		fields["requesters"], fields["approvers"], fields["max_duration"] = []string{"autogroup:member"}, []string{"bob@example.com"}, "1h"
		return fields
	}
	groups := []map[string]string{{"name": googleAdminsA}}

	var both, older, one flow
	if code := call(t, srv, "root", "POST", "/v1/workflows", people(map[string]any{"name": "On-call", "grants": map[string]any{
		"tailscale": map[string]any{"attribute": "oncall"},
		"google":    map[string]any{"groups": groups},
	}, "resources": []map[string]string{{"name": "tag:prod"}}}), &both); code != 201 {
		t.Fatalf("creating with grants = %d", code)
	}
	check("created with grants", both, "custom:jit_oncall", true, "tag:prod")

	// The older layout is still read, and answered in the new one.
	if code := call(t, srv, "root", "POST", "/v1/workflows", people(map[string]any{
		"name": "Databases", "attribute": "db_ro", "resources": []map[string]string{{"name": "svc:mysql-prod"}},
	}), &older); code != 201 {
		t.Fatalf("creating in the older layout = %d", code)
	}
	check("created in the older layout", older, "custom:jit_db_ro", false, "svc:mysql-prod")

	// A kind that is left out is not granted. What a flow gives access to
	// belongs to the flow, not to Tailscale access: a flow that grants
	// groups only can say it too, and keeps it through a GET and a PUT.
	if code := call(t, srv, "root", "POST", "/v1/workflows", people(map[string]any{"name": "AWS admin", "grants": map[string]any{
		"google": map[string]any{"groups": groups},
	}, "resources": []map[string]string{{"name": "aws-prod"}}}), &one); code != 201 {
		t.Fatalf("creating with Google groups only = %d", code)
	}
	check("Google groups only", one, "", true, "aws-prod")
	var asRead map[string]any
	if code := call(t, srv, "root", "GET", "/v1/workflows/"+one.ID, nil, &asRead); code != 200 {
		t.Fatalf("reading the groups-only flow = %d", code)
	}
	var saved flow
	if code := call(t, srv, "root", "PUT", "/v1/workflows/"+one.ID, asRead, &saved); code != 200 {
		t.Fatalf("saving the groups-only flow as it was read = %d", code)
	}
	check("Google groups only, saved as read", saved, "", true, "aws-prod")

	var list struct {
		Workflows []flow `json:"workflows"`
	}
	if code := call(t, srv, "root", "GET", "/v1/workflows", nil, &list); code != 200 || len(list.Workflows) != 3 {
		t.Fatalf("listing = %d, %d flows", code, len(list.Workflows))
	}
	for _, f := range list.Workflows {
		if f.ID == both.ID {
			check("listed", f, "custom:jit_oncall", true, "tag:prod")
		}
	}

	// What GET answers can be sent back as it is, read-only fields and all.
	var raw map[string]any
	if code := call(t, srv, "root", "GET", "/v1/workflows/"+both.ID, nil, &raw); code != 200 {
		t.Fatalf("reading = %d", code)
	}
	var again flow
	if code := call(t, srv, "root", "PUT", "/v1/workflows/"+both.ID, raw, &again); code != 200 {
		t.Fatalf("saving a flow as it was read = %d", code)
	}
	check("saved as read", again, "custom:jit_oncall", true, "tag:prod")

	var e apiErr
	// "resources" is the flow's, so it is not read under grants.tailscale;
	// and a value of the wrong kind is refused in the API's own words.
	if code := call(t, srv, "root", "POST", "/v1/workflows", people(map[string]any{"name": "Nested", "grants": map[string]any{
		"tailscale": map[string]any{"attribute": "nested", "resources": []map[string]string{{"name": "tag:prod"}}},
	}}), &e); code != 400 || !strings.Contains(e.Error.Message, `unknown field "resources"`) {
		t.Errorf("resources under grants.tailscale = %d %q, want 400", code, e.Error.Message)
	}
	if code := call(t, srv, "root", "POST", "/v1/workflows", people(map[string]any{"name": "Strings", "grants": map[string]any{
		"google": map[string]any{"groups": []string{googleAdminsA}},
	}}), &e); code != 400 || !strings.Contains(e.Error.Message, "grants.google.groups") || !strings.Contains(e.Error.Message, "takes an object, and the body has a string there") || strings.Contains(e.Error.Message, "jit.") {
		t.Errorf("groups as strings = %d %q, want 400 that names the field and no Go type", code, e.Error.Message)
	}
	raw["attribute"] = "oncall"
	if code := call(t, srv, "root", "PUT", "/v1/workflows/"+both.ID, raw, &e); code != 400 || !strings.Contains(e.Error.Message, "not in both") {
		t.Errorf("a body in both layouts = %d %q, want 400", code, e.Error.Message)
	}
	// Nothing under grants grants nothing, which no flow may do.
	if code := call(t, srv, "root", "POST", "/v1/workflows", people(map[string]any{"name": "Empty", "grants": map[string]any{}}), &e); code != 400 || !strings.Contains(e.Error.Message, "must grant something") {
		t.Errorf("a flow that grants nothing = %d %q, want 400", code, e.Error.Message)
	}
}
