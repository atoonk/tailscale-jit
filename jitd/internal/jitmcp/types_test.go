package jitmcp

import (
	"strings"
	"testing"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

// A flow that grants Okta groups only changes nothing on the device. The
// text an agent reads says what it does instead of "in place on this
// device", and names the groups as quoted data.
func TestOktaOnlyFlowText(t *testing.T) {
	me := identity{Login: "maya@example.com", DeviceID: "n1", DeviceName: "maya-laptop"}
	groups := []oktaGroup{{ID: "00g1", Name: "AWS-Prod-ReadOnly"}}
	txt := summarizeRequestable(listRequestableOutput{Identity: me, Requestable: []requestableFlow{
		{WorkflowID: "wf_1", WorkflowName: "AWS read", OktaGroups: groups, MaxDuration: "1h", AutoApprove: true}}})
	if !strings.Contains(txt, `adds the requester to the Okta group "AWS-Prod-ReadOnly"`) || strings.Contains(txt, "not described by the admin") {
		t.Errorf("list_requestable text:\n%s", txt)
	}
	r := accessRequest{ID: "req_1", WorkflowName: "AWS read", OktaGroups: groups, Status: string(jit.StatusApproved),
		Requester: me, TargetDeviceID: "n1", Enforcement: enforcement{ConfirmedAt: "2026-11-16T10:00:00Z"}}
	txt = summarizeRequest(r, me)
	if !strings.Contains(txt, `The requester is in the Okta group "AWS-Prod-ReadOnly"`) || strings.Contains(txt, "in place on this device") {
		t.Errorf("request text:\n%s", txt)
	}
}
