package jithttp

import (
	"strings"
)

// openAPI returns the OpenAPI 3 description of the /v1 API with this server's
// base URL filled in. It is written by hand; the contract test in
// openapi_test.go checks that every route the mux serves is documented.
func (s *Server) openAPI() string {
	return strings.ReplaceAll(openAPISpec, "{{BASE}}", s.base())
}

const openAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Tailscale JIT access",
    "version": "1",
    "description": "Request time-limited access through approval flows (each sets one posture attribute on your device), approve requests, and manage the flows.\n\n**Identity.** There is no login. The server is a tsnet node; it identifies every caller from the Tailscale connection (WhoIs). Call it from a device on the tailnet. Tagged devices (for example an agent on ` + "`tag:agent`" + `) are identified by their tags.\n\n**Roles.** Admins (` + "`-admins`" + `) manage approval flows and see every request. Everyone else sees their own requests and the ones they approve for. Requests outside your view return 404.\n\n**Typical client flow.** ` + "`GET /v1/requestable`" + ` → ` + "`POST /v1/requests`" + ` → tell the user the ` + "`url`" + ` → poll ` + "`GET /v1/requests/{id}`" + ` every few seconds until ` + "`status`" + ` leaves ` + "`pending`" + ` → use the service → optionally ` + "`POST /v1/requests/{id}/revoke`" + ` when done.\n\n**Errors** are an object with an error field holding code and message (see ErrorBody). A duplicate submission returns 409 with ` + "`request_id`" + ` and ` + "`url`" + ` of the live request."
  },
  "externalDocs": {"description": "jitd on GitHub: install guide, rules and source", "url": "https://github.com/atoonk/tailscale-jit/tree/main/jitd"},
  "servers": [{"url": "{{BASE}}"}],
  "tags": [
    {"name": "me", "description": "Who am I"},
    {"name": "requests", "description": "Access requests"},
    {"name": "workflows", "description": "Approval flows (admins)"},
    {"name": "policy", "description": "Tailscale policy helpers (admins)"}
  ],
  "paths": {
    "/v1/me": {"get": {"tags": ["me"], "summary": "The caller, as identified by Tailscale", "operationId": "me",
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Me"}}}}, "401": {"$ref": "#/components/responses/Error"}}}},
    "/v1/requestable": {"get": {"tags": ["requests"], "summary": "Approval flows the caller may request through", "operationId": "listRequestable",
      "description": "One entry per flow, with what it gives access to (resources), what the tailnet policy actually grants for its attribute, and the caller's live request through it, if any.",
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {
        "identity": {"$ref": "#/components/schemas/Identity"},
        "requestable": {"type": "array", "items": {"$ref": "#/components/schemas/Requestable"}}}}}}}, "401": {"$ref": "#/components/responses/Error"}}}},
    "/v1/requests": {
      "get": {"tags": ["requests"], "summary": "List requests the caller may see", "operationId": "listRequests",
        "parameters": [
          {"name": "scope", "in": "query", "schema": {"type": "string", "enum": ["mine", "approvals", "all"]}, "description": "mine: submitted by or targeting the caller; approvals: other people's requests through flows the caller approves for; all (default): everything the caller may see"},
          {"name": "status", "in": "query", "schema": {"$ref": "#/components/schemas/Status"}}],
        "responses": {"200": {"description": "Newest first", "content": {"application/json": {"schema": {"type": "object", "properties": {"requests": {"type": "array", "items": {"$ref": "#/components/schemas/AccessRequest"}}}}}}}, "401": {"$ref": "#/components/responses/Error"}}},
      "post": {"tags": ["requests"], "summary": "Submit an access request", "operationId": "submitRequest",
        "description": "Access is granted to the caller's own device once approved. Tell the user the returned ` + "`url`" + `; a person approves there.",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewRequest"}}}},
        "responses": {"201": {"description": "Pending", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccessRequest"}}}},
          "400": {"$ref": "#/components/responses/Error"}, "403": {"$ref": "#/components/responses/Error"},
          "404": {"description": "No such approval flow", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}},
          "409": {"description": "The flow is disabled, not enough other people could ever approve it, or a live request for this flow and device already exists (then its id and url are in the error)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}}}}},
    "/v1/requests/{id}": {"get": {"tags": ["requests"], "summary": "One request with its timeline", "operationId": "getRequest",
      "description": "Poll this to wait for a decision. ` + "`enforcement.confirmed_at`" + ` is set once the device attribute was read back from Tailscale.",
      "parameters": [{"$ref": "#/components/parameters/id"}],
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccessRequest"}}}}, "404": {"$ref": "#/components/responses/Error"}}}},
    "/v1/requests/{id}/approve": {"post": {"tags": ["requests"], "summary": "Approve (approvers)", "operationId": "approveRequest",
      "description": "One vote per approver. Votes are counted against the flow as it is now: only current approvers count, and the requester only while the flow allows self-approval. Access is granted once the flow's ` + "`approvals_required`" + ` is reached; an approver who already voted can call this again to grant once enough votes are in (e.g. after the quorum was lowered).",
      "parameters": [{"$ref": "#/components/parameters/id"}], "requestBody": {"$ref": "#/components/requestBodies/Note"},
      "responses": {"200": {"$ref": "#/components/responses/Request"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"description": "No such request, or not one the caller may see"}, "409": {"$ref": "#/components/responses/Error"}, "502": {"$ref": "#/components/responses/APIFailed"}}}},
    "/v1/requests/{id}/decline": {"post": {"tags": ["requests"], "summary": "Decline with a reason (approvers, admins)", "operationId": "declineRequest",
      "parameters": [{"$ref": "#/components/parameters/id"}], "requestBody": {"$ref": "#/components/requestBodies/Reason"},
      "responses": {"200": {"$ref": "#/components/responses/Request"}, "400": {"$ref": "#/components/responses/Error"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}}}},
    "/v1/requests/{id}/cancel": {"post": {"tags": ["requests"], "summary": "Withdraw a pending request (requester)", "operationId": "cancelRequest",
      "parameters": [{"$ref": "#/components/parameters/id"}], "requestBody": {"$ref": "#/components/requestBodies/Note"},
      "responses": {"200": {"$ref": "#/components/responses/Request"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}}}},
    "/v1/requests/{id}/revoke": {"post": {"tags": ["requests"], "summary": "End approved access early (requester, approvers, admins)", "operationId": "revokeRequest",
      "parameters": [{"$ref": "#/components/parameters/id"}], "requestBody": {"$ref": "#/components/requestBodies/Note"},
      "responses": {"200": {"$ref": "#/components/responses/Request"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}, "502": {"$ref": "#/components/responses/APIFailed"}}}},
    "/v1/workflows": {
      "get": {"tags": ["workflows"], "summary": "All approval flows", "operationId": "listWorkflows",
        "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"workflows": {"type": "array", "items": {"$ref": "#/components/schemas/Workflow"}}}}}}}, "403": {"$ref": "#/components/responses/Error"}}},
      "post": {"tags": ["workflows"], "summary": "Create an approval flow", "operationId": "createWorkflow",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Workflow"}}}},
        "responses": {"201": {"$ref": "#/components/responses/Workflow"}, "400": {"$ref": "#/components/responses/Error"}, "403": {"$ref": "#/components/responses/Error"}, "409": {"description": "Another flow already sets this attribute", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}}}}},
    "/v1/workflows/{id}": {
      "get": {"tags": ["workflows"], "summary": "One approval flow", "operationId": "getWorkflow", "parameters": [{"$ref": "#/components/parameters/id"}],
        "responses": {"200": {"$ref": "#/components/responses/Workflow"}, "404": {"$ref": "#/components/responses/Error"}}},
      "put": {"tags": ["workflows"], "summary": "Replace an approval flow", "operationId": "updateWorkflow", "parameters": [{"$ref": "#/components/parameters/id"}],
        "description": "Pending requests follow the change: a new attribute expires them (the requester files again), a new quorum applies to them.",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Workflow"}}}},
        "responses": {"200": {"$ref": "#/components/responses/Workflow"}, "400": {"$ref": "#/components/responses/Error"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"$ref": "#/components/responses/Error"}, "409": {"description": "Another flow already sets this attribute", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}}}},
      "delete": {"tags": ["workflows"], "summary": "Delete an approval flow with no live requests", "operationId": "deleteWorkflow", "parameters": [{"$ref": "#/components/parameters/id"}],
        "responses": {"204": {"description": "Deleted"}, "409": {"$ref": "#/components/responses/Error"}}}},
    "/v1/setup": {"get": {"tags": ["policy"], "summary": "Result of the last setup check: do the Tailscale API credentials work (never the credentials themselves)", "operationId": "setup",
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Setup"}}}}, "403": {"$ref": "#/components/responses/Error"}}}},
    "/v1/setup/check": {"post": {"tags": ["policy"], "summary": "Re-read the credentials file and run the setup check again", "operationId": "setupCheck",
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Setup"}}}}, "403": {"$ref": "#/components/responses/Error"}}}},
    "/v1/policy-snippet": {"get": {"tags": ["policy"], "summary": "Postures and grants to merge into the tailnet policy", "operationId": "policySnippet",
      "description": "Each posture and grant is marked as already in the current policy file or NEW (unmarked if the policy cannot be read).",
      "parameters": [{"name": "missing", "in": "query", "schema": {"type": "string", "enum": ["1"]}, "description": "1: leave out what the policy already has"}],
      "responses": {"200": {"description": "HuJSON text", "content": {"text/plain": {"schema": {"type": "string"}}}}, "403": {"$ref": "#/components/responses/Error"}}}},
    "/v1/devices/{id}/attributes": {"get": {"tags": ["policy"], "summary": "A device's posture attributes, straight from the Tailscale API", "operationId": "deviceAttributes",
      "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "Tailscale node ID, e.g. nABC123CNTRL"}],
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"attributes": {"type": "object"}, "expiries": {"type": "object"}}}}}}, "502": {"$ref": "#/components/responses/Error"}}}},
    "/v1/changes": {"get": {"tags": ["me"], "summary": "A counter that increases whenever anything changes (pages poll it)", "operationId": "changes",
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"changes": {"type": "integer"}}}}}}}}}
  },
  "components": {
    "parameters": {"id": {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "example": "req_ec77cc3939cd0d5d"}},
    "requestBodies": {
      "Note": {"content": {"application/json": {"schema": {"type": "object", "properties": {"note": {"type": "string"}}}}}},
      "Reason": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["note"], "properties": {"note": {"type": "string", "description": "Why it was declined"}}}}}}
    },
    "responses": {
      "Request": {"description": "The updated request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccessRequest"}}}},
      "Workflow": {"description": "The approval flow", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Workflow"}}}},
      "Error": {"description": "Error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}}},
      "APIFailed": {"description": "The Tailscale API call failed. The action was recorded (approve_failed / revoke_failed) and the request is returned with the error; retry later", "content": {"application/json": {"schema": {"type": "object", "properties": {"error": {"$ref": "#/components/schemas/ErrorBody/properties/error"}, "request": {"$ref": "#/components/schemas/AccessRequest"}}}}}}
    },
    "schemas": {
      "Setup": {"type": "object", "properties": {
        "checked_at": {"type": "string", "format": "date-time"}, "ok": {"type": "boolean"},
        "credentials": {"type": "object", "properties": {"kind": {"type": "string", "enum": ["oauth", "api_key", ""]}, "file": {"type": "string"}, "file_exists": {"type": "boolean"}, "file_error": {"type": "string"}, "from_file": {"type": "array", "items": {"type": "string"}}, "from_env": {"type": "array", "items": {"type": "string"}}}},
        "node": {"type": "object", "properties": {"id": {"type": "string"}, "dns_name": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}}},
        "tag": {"type": "string"},
        "transient": {"type": "boolean", "description": "A check failed for a reason that says nothing about the credential (e.g. network); it stays in use and the check is retried"},
        "checks": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "ok": {"type": "boolean"}, "skipped": {"type": "boolean"}, "detail": {"type": "string"}, "fix": {"type": "string"}}}}}},
      "Status": {"type": "string", "enum": ["pending", "approved", "declined", "expired", "revoked", "cancelled"]},
      "Principal": {"type": "string", "description": "A login (alice@example.com), group:<name> from the policy file, tag:<name>, or autogroup:member", "example": "group:sre"},
      "Duration": {"type": "string", "description": "Go duration (15m, 1h30m), optionally with leading whole days (3d, 1d12h); no signs. Responses use Go's form, e.g. 72h0m0s. A number is taken as nanoseconds", "example": "1h0m0s"},
      "Identity": {"type": "object", "properties": {
        "login": {"type": "string", "example": "alice@example.com"}, "display_name": {"type": "string"},
        "device_id": {"type": "string", "example": "nABC123CNTRL"}, "device_name": {"type": "string", "example": "alice-laptop"},
        "tags": {"type": "array", "items": {"type": "string"}, "description": "Set for tagged devices; such callers have no login"}}},
      "Me": {"allOf": [{"$ref": "#/components/schemas/Identity"}, {"type": "object", "properties": {"admin": {"type": "boolean"}}}]},
      "Requestable": {"type": "object", "properties": {
        "workflow_id": {"type": "string"}, "workflow_name": {"type": "string"}, "description": {"type": "string"},
        "attribute": {"type": "string", "description": "The posture attribute an approval sets on your device", "example": "custom:jit_db_ro"},
        "resources": {"type": "array", "items": {"$ref": "#/components/schemas/Resource"}, "description": "Gives access to: what the policy unlocks for the attribute, as described by the admin"},
        "policy": {"$ref": "#/components/schemas/PolicyUse"},
        "max_duration": {"$ref": "#/components/schemas/Duration"}, "default_duration": {"$ref": "#/components/schemas/Duration"},
        "approvers": {"type": "array", "items": {"$ref": "#/components/schemas/Principal"}},
        "allow_self_approval": {"type": "boolean"}, "approvals_required": {"type": "integer"},
        "active_request_id": {"type": "string", "description": "The caller's live request through this flow, if any"},
        "active_request_url": {"type": "string"}, "active_status": {"$ref": "#/components/schemas/Status"},
        "active_expires_at": {"type": "string", "format": "date-time"}}},
      "NewRequest": {"type": "object", "required": ["workflow_id", "reason"], "properties": {
        "workflow_id": {"type": "string"},
        "duration": {"$ref": "#/components/schemas/Duration"},
        "reason": {"type": "string", "description": "What you need to do and why; shown to the approver"}}},
      "Approval": {"type": "object", "properties": {"actor": {"type": "string"}, "device_id": {"type": "string", "description": "The approver's device; tells tagged approvers apart"}, "note": {"type": "string"}, "at": {"type": "string", "format": "date-time"}}},
      "Enforcement": {"type": "object", "description": "What was verified on the device, separate from what was requested", "properties": {
        "confirmed_at": {"type": "string", "format": "date-time", "description": "The attribute was read back present after approval"},
        "removed_at": {"type": "string", "format": "date-time", "description": "The attribute was read back absent after expiry or revoke"},
        "checked_at": {"type": "string", "format": "date-time"}, "error": {"type": "string"}}},
      "Event": {"type": "object", "properties": {
        "type": {"type": "string", "enum": ["submitted", "approval", "approved", "approve_failed", "declined", "cancelled", "revoked", "revoke_failed", "expired"]},
        "actor": {"type": "string"}, "note": {"type": "string"}, "at": {"type": "string", "format": "date-time"}}},
      "AccessRequest": {"type": "object", "properties": {
        "id": {"type": "string", "example": "req_ec77cc3939cd0d5d"}, "url": {"type": "string", "description": "The approval page; show this to the user"},
        "workflow_id": {"type": "string"}, "workflow_name": {"type": "string"},
        "attribute": {"type": "string", "example": "custom:jit_db_ro"},
        "resources": {"type": "array", "items": {"$ref": "#/components/schemas/Resource"}},
        "requester": {"$ref": "#/components/schemas/Identity"}, "target_device_id": {"type": "string"},
        "duration": {"$ref": "#/components/schemas/Duration"}, "reason": {"type": "string"},
        "status": {"$ref": "#/components/schemas/Status"},
        "approvals": {"type": "array", "items": {"$ref": "#/components/schemas/Approval"}}, "approvals_required": {"type": "integer"},
        "approvals_counted": {"type": "integer", "description": "how many of approvals still count under the flow as it is now (pending requests); otherwise every vote cast"},
        "enforcement": {"$ref": "#/components/schemas/Enforcement"},
        "timeline": {"type": "array", "items": {"$ref": "#/components/schemas/Event"}},
        "approved_at": {"type": "string", "format": "date-time"}, "expires_at": {"type": "string", "format": "date-time"},
        "attributes": {"type": "array", "items": {"type": "string"}, "description": "The attribute, once approval set it; empty if access was never granted", "example": ["custom:jit_db_ro"]},
        "policy": {"$ref": "#/components/schemas/PolicyUse"},
        "last_error": {"type": "string"}, "created_at": {"type": "string", "format": "date-time"}, "updated_at": {"type": "string", "format": "date-time"}}},
      "Resource": {"type": "object", "required": ["name"], "properties": {
        "name": {"type": "string", "description": "As it appears in a policy grant: svc:, tag:, a host, a CIDR", "example": "svc:mysql-prod"},
        "description": {"type": "string", "example": "Production MySQL, orders and customers (us-east-1)"}}},
      "PolicyUse": {"type": "object", "description": "What the tailnet policy says about the flow's posture attribute", "properties": {
        "posture": {"type": "string", "example": "posture:jit_db_ro"}, "defined": {"type": "boolean"},
        "grants": {"type": "array", "items": {"type": "string"}, "description": "Destinations of every grant gated on the posture"},
        "unreferenced": {"type": "boolean", "description": "No grant uses the posture: approving unlocks nothing"},
        "missing": {"type": "array", "items": {"type": "string"}}, "extra": {"type": "array", "items": {"type": "string"}},
        "error": {"type": "string", "description": "Set when the policy could not be read; the other fields are then unknown"}}},
      "Workflow": {"type": "object", "required": ["name", "attribute", "requesters", "approvers"], "properties": {
        "id": {"type": "string", "readOnly": true}, "name": {"type": "string", "example": "Database access (read-only)"}, "description": {"type": "string"},
        "attribute": {"type": "string", "description": "custom:jit_<name>; the prefix may be omitted when writing", "example": "custom:jit_db_ro"},
        "resources": {"type": "array", "items": {"$ref": "#/components/schemas/Resource"}},
        "requesters": {"type": "array", "items": {"$ref": "#/components/schemas/Principal"}},
        "approvers": {"type": "array", "items": {"$ref": "#/components/schemas/Principal"}},
        "allow_self_approval": {"type": "boolean"}, "approvals_required": {"type": "integer", "default": 1, "minimum": 1, "maximum": 10},
        "max_duration": {"allOf": [{"$ref": "#/components/schemas/Duration"}], "description": "1 minute to 365 days"},
        "default_duration": {"allOf": [{"$ref": "#/components/schemas/Duration"}], "description": "At most max_duration"},
        "approval_timeout": {"allOf": [{"$ref": "#/components/schemas/Duration"}], "description": "1 minute to 365 days; pending requests expire after this"}, "disabled": {"type": "boolean"},
        "created_at": {"type": "string", "format": "date-time", "readOnly": true}, "updated_at": {"type": "string", "format": "date-time", "readOnly": true}}},
      "ErrorBody": {"type": "object", "properties": {"error": {"type": "object", "properties": {
        "code": {"type": "string", "enum": ["bad_request", "forbidden", "not_found", "conflict", "identity_unavailable", "tailscale_api_error", "internal"]},
        "message": {"type": "string"}, "request_id": {"type": "string"}, "url": {"type": "string"}}}}}
    }
  }
}`

// swaggerPage renders the spec with Swagger UI, loaded from a CDN: the page
// is only reachable over the tailnet, but the browser fetches the UI assets
// from the internet.
const swaggerPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>API · Tailscale JIT access</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui.min.css">
<style>body{margin:0} .topbar{display:none} .swagger-ui .info{margin:24px 0}</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-bundle.min.js"></script>
<script>
window.ui = SwaggerUIBundle({url: "/api/openapi.json", dom_id: "#swagger-ui", deepLinking: true, tryItOutEnabled: true});
</script>
</body>
</html>`
