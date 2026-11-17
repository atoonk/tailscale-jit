package slackbot

import (
	"strings"
	"testing"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
)

// The all-clear to an admin says what is true: a group another running
// request holds was not removed.
func TestOktaAllClearNamesKeptGroups(t *testing.T) {
	now := time.Now()
	r := &jit.AccessRequest{ID: "req_1", WorkflowName: "AWS admin", Status: jit.StatusExpired,
		Requester:  jit.Identity{Login: "maya@example.com"},
		OktaGroups: []jit.OktaGroup{{ID: "g1", Name: "AWS-Prod-Admin"}, {ID: "g2", Name: "AWS-Prod-ReadOnly"}},
		Okta:       &jit.OktaGrant{UserID: "u1", Login: "maya@example.com", Added: []string{"g1", "g2"}, RemovedAt: &now}}
	text := func(m slack.Message) string { return m.Text + " " + blocksJSON(m) }
	if got := text(renderGroupAlert(r, "http://jit/requests/req_1")); !strings.Contains(got, "is out of AWS-Prod-Admin, AWS-Prod-ReadOnly") || strings.Contains(got, "another running request") {
		t.Errorf("all removed: %s", got)
	}
	r.Okta.Kept = []string{"g2"}
	got := text(renderGroupAlert(r, "http://jit/requests/req_1"))
	if !strings.Contains(got, "is out of AWS-Prod-Admin and stays in AWS-Prod-ReadOnly") || !strings.Contains(got, "another running request") {
		t.Errorf("one kept: %s", got)
	}
	r.Okta.Kept = []string{"g1", "g2"}
	got = text(renderGroupAlert(r, "http://jit/requests/req_1"))
	if strings.Contains(got, "is out of") || strings.Contains(got, "went through") || !strings.Contains(got, "stays in AWS-Prod-Admin, AWS-Prod-ReadOnly") {
		t.Errorf("all kept: %s", got)
	}
	if s := statusLine(r, 0); !strings.Contains(s, "still held the Okta group AWS-Prod-Admin, AWS-Prod-ReadOnly") {
		t.Errorf("request message: %s", s)
	}
}

// A request with Okta and Google groups gets one alert, which names each
// kind the admins were alerted about and leaves the other out.
func TestGroupAlertNamesEachKind(t *testing.T) {
	now := time.Now()
	r := &jit.AccessRequest{ID: "req_1", WorkflowName: "Prod admin", Status: jit.StatusExpired,
		Requester:    jit.Identity{Login: "maya@example.com"},
		OktaGroups:   []jit.OktaGroup{{ID: "g1", Name: "AWS-Prod-Admin"}},
		Okta:         &jit.OktaGrant{UserID: "u1", Login: "maya@example.com", Added: []string{"g1"}, RemovedAt: &now},
		GoogleGroups: []jit.GroupRef{{ID: "gg1", Name: "gcp-prod-admins@example.com"}},
		Google: &jit.GroupGrant{UserID: "maya@example.com", Login: "maya@example.com", Added: []string{"gg1"},
			AlertedAt: &now, Error: "403 forbidden"}}
	m := renderGroupAlert(r, "http://jit/requests/req_1")
	got := m.Text + " " + blocksJSON(m)
	for _, want := range []string{"Google removal is failing: maya@example.com is still in gcp-prod-admins@example.com", "take the user out in Google", "403 forbidden"} {
		if !strings.Contains(got, want) {
			t.Errorf("the alert lacks %q: %s", want, got)
		}
	}
	if strings.Contains(got, "Okta") {
		t.Errorf("the alert speaks of Okta, whose removal went through: %s", got)
	}
	if s := statusLine(r, 0); !strings.Contains(s, "still in the Google group gcp-prod-admins@example.com") || strings.Contains(s, "Okta") {
		t.Errorf("request message: %s", s)
	}
	r.Google.RemovedAt = &now
	m = renderGroupAlert(r, "http://jit/requests/req_1")
	if got := m.Text; got != "Google removal went through: maya@example.com is out of gcp-prod-admins@example.com" {
		t.Errorf("all-clear: %s", got)
	}
}
