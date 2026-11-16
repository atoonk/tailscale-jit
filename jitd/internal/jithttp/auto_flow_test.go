package jithttp

import (
	"strings"
	"testing"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

// Who made a flow automatic comes from the caller's identity, never from
// the body, and is shown with the flow.
func TestFlowRecordsWhoMadeItAutomatic(t *testing.T) {
	srv, _ := newTestServer(t)
	var w jit.Workflow
	body := map[string]any{"name": "ssh", "attribute": "ssh", "auto_approve": true, "auto_approve_by": "someone@else.example",
		"updated_by": "someone@else.example", "requesters": []string{"autogroup:member"}, "max_duration": "1h"}
	if code := call(t, srv, "root", "POST", "/v1/workflows", body, &w); code != 201 {
		t.Fatalf("create = %d", code)
	}
	if w.AutoApproveBy != "root@example.com" || w.UpdatedBy != "root@example.com" || w.AutoApproveAt == nil {
		t.Errorf("made automatic by %q, saved by %q, at %v", w.AutoApproveBy, w.UpdatedBy, w.AutoApproveAt)
	}
	if _, page := getPage(t, srv, "root", "/admin/workflows"); !strings.Contains(page, "set by root@example.com") {
		t.Error("the flows page does not say who made the flow automatic")
	}
}
