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
    "description": "Request time-limited access through approval flows (each sets one posture attribute on your device), approve requests, and manage the flows.\n\n**Identity.** There is no login. The server is a tsnet node; it identifies every caller from the Tailscale connection (WhoIs). Call it from a device on the tailnet. Tagged devices (for example an agent on ` + "`tag:agent`" + `) are identified by their tags.\n\n**Roles.** Admins (` + "`-admins`" + `) manage approval flows and see every request. Everyone else sees their own requests and the ones they approve for. Requests outside your view return 404.\n\n**Typical client flow.** ` + "`GET /v1/requestable`" + ` → ` + "`POST /v1/requests`" + ` → tell the user the ` + "`url`" + ` → poll ` + "`GET /v1/requests/{id}`" + ` every few seconds until ` + "`status`" + ` leaves ` + "`pending`" + ` → use the service → optionally ` + "`POST /v1/requests/{id}/revoke`" + ` when done.\n\n**Errors** are an object with an error field holding code and message (see ErrorBody). A duplicate submission returns 409 with ` + "`request_id`" + ` and ` + "`url`" + ` of the live request.\n\n**MCP.** Agents don't need this API: jitd is also an MCP server at ` + "`POST /mcp`" + ` (Streamable HTTP, stateless, same identity rules) with the tools ` + "`list_requestable`, `request_access`, `wait_for_access`, `get_access_request` and `cancel_access_request`" + `, and an MCP Apps view for hosts that render one. See the ` + "`mcp`" + ` section below."
  },
  "externalDocs": {"description": "jitd on GitHub: install guide, rules and source", "url": "https://github.com/atoonk/tailscale-jit/tree/main/jitd"},
  "servers": [{"url": "{{BASE}}"}],
  "tags": [
    {"name": "me", "description": "Who am I"},
    {"name": "requests", "description": "Access requests"},
    {"name": "workflows", "description": "Approval flows (admins)"},
    {"name": "policy", "description": "Tailscale policy helpers (admins)"},
    {"name": "okta", "description": "The Okta credentials (admins). The private key and the API token are never returned"},
    {"name": "google", "description": "The Google service account and its limits (admins). The key is never returned"},
    {"name": "slack", "description": "The Slack integration (admins). jitd connects out to Slack with Socket Mode; tokens are never returned"},
    {"name": "mcp", "description": "The MCP server, for agents. Not a REST endpoint: JSON-RPC 2.0 over Streamable HTTP, see https://modelcontextprotocol.io"}
  ],
  "paths": {
    "/mcp": {"post": {"tags": ["mcp"], "summary": "The MCP server (Streamable HTTP)", "operationId": "mcp",
      "description": "Point an MCP client at this URL; there is no login, the caller is identified from the Tailscale connection like everywhere else. Sessions are stateless: every message is one POST, answered with one JSON object (never an event stream, so proxies that buffer or time out streams are no concern). GET is not served.\n\n**Tools** (the agent acts as the caller, on the caller's device): ` + "`list_requestable`" + ` (the flows you may request through, with resources, policy check and your open request), ` + "`request_access`" + ` (workflow_id, reason, optional duration; returns the request and its approval url), ` + "`wait_for_access`" + ` (holds the call until the request is decided and the attribute is confirmed on the device, up to timeout_seconds, default 30, at most 50; the agent calls again to keep waiting. The requester's first call for a pending request returns at once with show_link_first, so the agent gives the user the approval link before anything blocks), ` + "`get_access_request`" + `, ` + "`cancel_access_request`" + ` (withdraws a pending request or revokes approved access). There is no approve tool. Text written by people (reasons, notes, descriptions) is returned quoted.\n\n**View.** Each tool names the MCP Apps resource ` + "`ui://jit/app`" + ` (` + "`text/html;profile=mcp-app`" + `): a card that follows the request and a form to pick a flow. Hosts without MCP Apps get the same information as text.\n\n**Connecting.** Claude Code: ` + "`claude mcp add --transport http --scope user jit {{BASE}}/mcp`" + `. VS Code: ` + "`{\\\"servers\\\": {\\\"jit\\\": {\\\"type\\\": \\\"http\\\", \\\"url\\\": \\\"{{BASE}}/mcp\\\"}}}`" + ` in .vscode/mcp.json. Claude Desktop starts only local servers: run ` + "`npx -y mcp-remote@0.16.5 {{BASE}}/mcp --transport http-only --allow-http`" + ` as the command (Node 20 or newer; drop --allow-http when jitd serves HTTPS).",
      "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "description": "A JSON-RPC 2.0 request, notification or response", "example": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}}}}},
      "responses": {"200": {"description": "The JSON-RPC response, as application/json", "content": {"application/json": {"schema": {"type": "object"}}}},
        "202": {"description": "Accepted (a notification or a response; nothing comes back)"}, "401": {"$ref": "#/components/responses/Error"}}}},
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
    "/v1/setup/credentials": {
      "put": {"tags": ["policy"], "summary": "Try a Tailscale API credential and, if every check passes, save it and serve with it", "operationId": "setupSave",
        "description": "Either an OAuth client (client_id and client_secret) or an api_key. Nothing is saved when a check fails (400); the message says which and why. Refused (409) when jitd's env file or environment sets a credential, which wins.",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {
          "client_id": {"type": "string"}, "client_secret": {"type": "string", "example": "tskey-client-..."}, "api_key": {"type": "string", "description": "An API access token, instead of an OAuth client", "example": "tskey-api-..."}}}}}},
        "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Setup"}}}}, "400": {"$ref": "#/components/responses/Error"}, "403": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}}},
      "delete": {"tags": ["policy"], "summary": "Forget the Tailscale API credential saved here", "operationId": "setupRemove",
        "description": "Approvals, revokes and clean-up fail until there is a credential again, unless the env file or the environment sets one.",
        "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Setup"}}}}, "403": {"$ref": "#/components/responses/Error"}}}},
    "/v1/policy-snippet": {"get": {"tags": ["policy"], "summary": "Postures and grants to merge into the tailnet policy", "operationId": "policySnippet",
      "description": "Each posture and grant is marked as already in the current policy file or NEW (unmarked if the policy cannot be read).",
      "parameters": [{"name": "missing", "in": "query", "schema": {"type": "string", "enum": ["1"]}, "description": "1: leave out what the policy already has"}],
      "responses": {"200": {"description": "HuJSON text", "content": {"text/plain": {"schema": {"type": "string"}}}}, "403": {"$ref": "#/components/responses/Error"}}}},
    "/v1/devices/{id}/attributes": {"get": {"tags": ["policy"], "summary": "A device's posture attributes, straight from the Tailscale API", "operationId": "deviceAttributes",
      "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "Tailscale node ID, e.g. nABC123CNTRL"}],
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"attributes": {"type": "object"}, "expiries": {"type": "object"}}}}}}, "502": {"$ref": "#/components/responses/Error"}}}},
    "/v1/okta": {
      "get": {"tags": ["okta"], "summary": "The Okta connection, without the key or the token", "operationId": "oktaStatus",
        "responses": {"200": {"$ref": "#/components/responses/Okta"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"$ref": "#/components/responses/Error"}}},
      "put": {"tags": ["okta"], "summary": "Sign in to Okta with these credentials and, if that works, save them", "operationId": "oktaSave",
        "description": "Either a service app (client_id and private_key) or an api_token. Nothing is saved when Okta refuses them (400). Replaces credentials saved here before. Refused (409) when the credentials come from jitd's environment or env file. The allowlists are not set here.",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["org_url"], "properties": {
          "org_url": {"type": "string", "example": "https://example.okta.com"}, "client_id": {"type": "string", "example": "0oa1abcdEFGHijkl2345"},
          "private_key": {"type": "string", "description": "The service app's private key, PEM (RSA or EC)"}, "private_key_id": {"type": "string", "description": "The key's kid, when the app has more than one key"},
          "scopes": {"type": "string", "description": "Scopes to ask for instead of okta.users.read okta.groups.manage, separated by spaces"},
          "api_token": {"type": "string", "description": "An API token, instead of a service app"}}}}}},
        "responses": {"200": {"$ref": "#/components/responses/Okta"}, "400": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}}},
      "delete": {"tags": ["okta"], "summary": "Forget the credentials saved here", "operationId": "oktaRemove",
        "description": "Memberships jitd added stay its to remove, and it cannot until Okta is set up again. While it holds any, this is refused (409) without force=1.",
        "parameters": [{"name": "force", "in": "query", "schema": {"type": "string", "enum": ["1"]}, "description": "1: remove although jitd still holds memberships"}],
        "responses": {"200": {"$ref": "#/components/responses/Okta"}, "409": {"$ref": "#/components/responses/Error"}}}},
    "/v1/okta/check": {"post": {"tags": ["okta"], "summary": "Try the credentials now, or say what jitd can tell about one group", "operationId": "oktaCheck",
      "description": "Reads only. Without a group: tries the credentials and returns the status. With one: looks it up and says whether a flow could grant it and whether it can be an okta: principal.",
      "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"group": {"type": "string", "description": "A group name or ID (00g…)"}}}}}},
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"status": {"$ref": "#/components/schemas/OktaStatus"}, "group": {"$ref": "#/components/schemas/OktaGroupCheck"}}}}}},
        "404": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}, "502": {"$ref": "#/components/responses/Error"}}}},
    "/v1/google": {
      "get": {"tags": ["google"], "summary": "The Google connection, without the key", "operationId": "googleStatus",
        "responses": {"200": {"$ref": "#/components/responses/Google"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"$ref": "#/components/responses/Error"}}},
      "put": {"tags": ["google"], "summary": "Save the Google settings; a new key is tried against Google first", "operationId": "googleSave",
        "description": "key is a service account's JSON key file, whole. Nothing is saved when Google refuses it (400). Leave key out to keep the one jitd has and change only the domains and groups; a list left out stays as it is saved. A value that jitd's environment or env file sets is not changed here; sending a key while one is set there is refused (409).",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {
          "key": {"type": "string", "description": "The service account's JSON key file, as Google downloaded it"},
          "allowed_domains": {"type": "string", "description": "Email domains whose users jitd may add to groups, separated by commas or spaces", "example": "example.com"},
          "grant_allowlist": {"type": "string", "description": "Groups a flow may grant, by address or ID, with * as a wildcard, separated by commas or spaces; * alone is every group", "example": "aws-*@example.com"}}}}}},
        "responses": {"200": {"$ref": "#/components/responses/Google"}, "400": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}}},
      "delete": {"tags": ["google"], "summary": "Forget the key and the limits saved here", "operationId": "googleRemove",
        "description": "Memberships jitd added stay its to remove, and it cannot until Google is set up again. While it holds any, this is refused (409) without force=1.",
        "parameters": [{"name": "force", "in": "query", "schema": {"type": "string", "enum": ["1"]}, "description": "1: remove although jitd still holds memberships"}],
        "responses": {"200": {"$ref": "#/components/responses/Google"}, "409": {"$ref": "#/components/responses/Error"}}}},
    "/v1/google/check": {"post": {"tags": ["google"], "summary": "Try the key now, or say what jitd can tell about one group", "operationId": "googleCheck",
      "description": "Reads only. Without a group: tries the key and returns the status. With one: looks it up and says whether a flow could grant it.",
      "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"group": {"type": "string", "description": "A group's email address", "example": "aws-admin@example.com"}}}}}},
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"status": {"$ref": "#/components/schemas/GoogleStatus"}, "group": {"$ref": "#/components/schemas/GoogleGroupCheck"}}}}}},
        "404": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}, "502": {"$ref": "#/components/responses/Error"}}}},
    "/v1/slack": {"get": {"tags": ["slack"], "summary": "The Slack connection, without the tokens", "operationId": "slackStatus",
      "responses": {"200": {"$ref": "#/components/responses/Slack"}, "403": {"$ref": "#/components/responses/Error"}, "404": {"$ref": "#/components/responses/Error"}}}},
    "/v1/slack/connect": {"post": {"tags": ["slack"], "summary": "Check the tokens with Slack, save them and connect", "operationId": "slackConnect",
      "description": "Replaces an earlier connection made here. Refused (409) when the tokens come from jitd's env file.",
      "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["bot_token", "app_token", "allowed_domains"], "properties": {
        "bot_token": {"type": "string", "description": "xoxb-…, the Bot User OAuth Token"}, "app_token": {"type": "string", "description": "xapp-…, an app-level token with connections:write"},
        "allowed_domains": {"type": "array", "items": {"type": "string"}, "example": ["example.com"]}}}}}},
      "responses": {"200": {"$ref": "#/components/responses/Slack"}, "400": {"$ref": "#/components/responses/Error"}, "409": {"$ref": "#/components/responses/Error"}}}},
    "/v1/slack/disconnect": {"post": {"tags": ["slack"], "summary": "Revoke the bot token in Slack, forget the tokens and disconnect", "operationId": "slackDisconnect",
      "responses": {"200": {"$ref": "#/components/responses/Slack"}, "409": {"$ref": "#/components/responses/Error"}}}},
    "/v1/slack/domains": {"put": {"tags": ["slack"], "summary": "Set the email domains Slack users are matched in", "operationId": "slackDomains",
      "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"allowed_domains": {"type": "array", "items": {"type": "string"}}}}}}},
      "responses": {"200": {"$ref": "#/components/responses/Slack"}, "400": {"$ref": "#/components/responses/Error"}}}},
    "/v1/slack/channels": {"get": {"tags": ["slack"], "summary": "Channels the bot can post to (public ones, and private ones it was invited to)", "operationId": "slackChannels",
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"channels": {"type": "array", "items": {"type": "object", "properties": {
        "id": {"type": "string", "example": "C0123456789"}, "name": {"type": "string"}, "is_private": {"type": "boolean"}, "is_member": {"type": "boolean"}}}}}}}}}, "502": {"$ref": "#/components/responses/Error"}}}},
    "/v1/slack/check": {"get": {"tags": ["slack"], "summary": "Per flow: can the bot post to its channel, and which approvers Slack matches to their login", "operationId": "slackCheck",
      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"flows": {"type": "array", "items": {"$ref": "#/components/schemas/SlackFlowCheck"}}}}}}}, "502": {"$ref": "#/components/responses/Error"}}}},
    "/v1/slack/test": {"post": {"tags": ["slack"], "summary": "Post a test message to a channel", "operationId": "slackTest",
      "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["channel"], "properties": {"channel": {"type": "string", "description": "Channel ID"}}}}}},
      "responses": {"200": {"description": "Sent"}, "400": {"$ref": "#/components/responses/Error"}}}},
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
      "Okta": {"description": "The Okta connection", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OktaStatus"}}}},
      "Google": {"description": "The Google connection", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GoogleStatus"}}}},
      "Slack": {"description": "The Slack connection", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SlackStatus"}}}},
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
      "OktaStatus": {"type": "object", "properties": {
        "source": {"type": "string", "enum": ["", "ui", "env"], "description": "Where the credentials come from: saved on the Okta page, or jitd's environment or env file; empty when not set up"},
        "env_file": {"type": "string"}, "shadowed": {"type": "boolean", "description": "Credentials saved on the page are ignored because the environment or the env file sets its own"},
        "enabled": {"type": "boolean", "description": "The credentials are complete and well-formed; error says whether Okta accepts them"},
        "auth": {"type": "string", "enum": ["service_app", "api_token"]}, "org_url": {"type": "string"}, "client_id": {"type": "string"}, "key_id": {"type": "string"},
        "key_fingerprint": {"type": "string", "description": "Tells keys apart: the start of the SHA-256 of the public key"}, "token_hint": {"type": "string", "example": "…a1b2"},
        "scopes": {"type": "array", "items": {"type": "string"}}, "saved_by": {"type": "string"}, "saved_at": {"type": "string", "format": "date-time"},
        "checked_at": {"type": "string", "format": "date-time"}, "error": {"type": "string"}, "fix": {"type": "string"},
        "grant_allowlist": {"type": "array", "items": {"type": "string"}, "description": "Groups a flow may grant; * is every group"}, "read_allowlist": {"type": "array", "items": {"type": "string"}},
        "held": {"type": "integer", "description": "Requests whose Okta memberships jitd still looks after"}}},
      "OktaGroupCheck": {"type": "object", "properties": {
        "id": {"type": "string"}, "name": {"type": "string"}, "type": {"type": "string", "example": "OKTA_GROUP"},
        "manageable": {"type": "boolean", "description": "Okta lets an API client change the members"}, "grant_allowed": {"type": "boolean"}, "read_allowed": {"type": "boolean"},
        "members": {"type": "integer"}, "members_capped": {"type": "boolean"}, "members_error": {"type": "string"}}},
      "GoogleStatus": {"type": "object", "properties": {
        "source": {"type": "string", "enum": ["", "ui", "env"], "description": "Where the key comes from: saved on the Google page, or jitd's environment or env file; empty when there is none"},
        "env_file": {"type": "string"}, "shadowed": {"type": "boolean", "description": "A key saved on the page is ignored because the environment or the env file sets its own"},
        "enabled": {"type": "boolean", "description": "There is a key and it is well-formed; error says whether Google accepts it"},
        "service_account": {"type": "string", "description": "The service account's address: what is given the Groups Admin role", "example": "jitd@my-project.iam.gserviceaccount.com"},
        "key_id": {"type": "string"}, "project": {"type": "string"}, "enable_url": {"type": "string", "description": "Where the Cloud Identity API is enabled for the project"},
        "saved_by": {"type": "string"}, "saved_at": {"type": "string", "format": "date-time"},
        "checked_at": {"type": "string", "format": "date-time"}, "error": {"type": "string"}, "fix": {"type": "string"},
        "allowed_domains": {"type": "array", "items": {"type": "string"}, "description": "Email domains whose users jitd may add; none means nobody"}, "allowed_domains_from_env": {"type": "boolean"},
        "grant_allowlist": {"type": "array", "items": {"type": "string"}, "description": "Groups a flow may grant; * is every group"}, "grant_allowlist_from_env": {"type": "boolean"},
        "held": {"type": "integer", "description": "Requests whose Google memberships jitd still looks after"}}},
      "GoogleGroupCheck": {"type": "object", "properties": {
        "id": {"type": "string"}, "email": {"type": "string"}, "name": {"type": "string"},
        "manageable": {"type": "boolean", "description": "False for a dynamic group, whose members come from a query"}, "grant_allowed": {"type": "boolean"}}},
      "SlackStatus": {"type": "object", "properties": {
        "source": {"type": "string", "enum": ["", "ui", "env"], "description": "Where the tokens come from: saved on the Slack page, or jitd's env file; empty when not set up"},
        "env_file": {"type": "string"}, "state": {"type": "string", "enum": ["off", "connecting", "connected", "error"]}, "since": {"type": "string", "format": "date-time"}, "last_error": {"type": "string"},
        "team_name": {"type": "string"}, "team_url": {"type": "string"}, "bot_name": {"type": "string"},
        "bot_token_hint": {"type": "string", "example": "…a1b2"}, "app_token_hint": {"type": "string"},
        "allowed_domains": {"type": "array", "items": {"type": "string"}}, "connected_by": {"type": "string"}, "connected_at": {"type": "string", "format": "date-time"},
        "manifest_url": {"type": "string", "description": "Creates the Slack app with everything jitd needs"}}},
      "SlackFlowCheck": {"type": "object", "properties": {
        "workflow_id": {"type": "string"}, "workflow_name": {"type": "string"}, "channel": {"type": "string"}, "channel_name": {"type": "string"},
        "channel_issue": {"type": "string", "description": "Why the bot cannot post there, if it cannot"}, "dm_approvers": {"type": "boolean"}, "browser_only": {"type": "boolean"},
        "approvers": {"type": "array", "items": {"type": "object", "properties": {"login": {"type": "string"}, "slack_user": {"type": "string", "example": "@sam"}, "problem": {"type": "string"}}}},
        "approver_issue": {"type": "string", "description": "Why the approver list may be incomplete (group members could not be read)"},
        "members": {"type": "boolean", "description": "autogroup:member approves: anyone on the tailnet, from Slack too if their Slack email is their Tailscale login"},
        "other_approvers": {"type": "array", "items": {"type": "string"}, "description": "tag: approvers; devices decide in the browser or through the API"}}},
      "WorkflowSlack": {"type": "object", "description": "Where requests through the flow are announced in Slack", "properties": {
        "channel": {"type": "string", "description": "Channel ID; empty for none", "example": "C0123456789"}, "channel_name": {"type": "string", "example": "sre-oncall"},
        "dm_approvers": {"type": "boolean", "description": "Also send each approver a direct message"},
        "browser_only": {"type": "boolean", "description": "No Approve/Decline buttons in Slack; decide in the browser"}}},
      "Status": {"type": "string", "enum": ["pending", "scheduled", "approved", "declined", "expired", "revoked", "cancelled"], "description": "scheduled: approved, for a window that has not started yet (nothing is granted until it does)"},
      "Principal": {"type": "string", "description": "A login (alice@example.com), group:<name> from the policy file, tag:<name>, or autogroup:member", "example": "group:sre"},
      "Duration": {"type": "string", "description": "Go duration (15m, 1h30m), optionally with leading whole days (3d, 1d12h); no signs. Responses use Go's form, e.g. 72h0m0s. A number is taken as nanoseconds", "example": "1h0m0s"},
      "Identity": {"type": "object", "properties": {
        "login": {"type": "string", "example": "alice@example.com"}, "display_name": {"type": "string"},
        "device_id": {"type": "string", "example": "nABC123CNTRL"}, "device_name": {"type": "string", "example": "alice-laptop"},
        "tags": {"type": "array", "items": {"type": "string"}, "description": "Set for tagged devices; such callers have no login"},
        "via": {"type": "string", "enum": ["slack"], "description": "Set when the caller was identified by their Slack account's email rather than by Tailscale"}, "slack_user": {"type": "string", "description": "With via slack: the Slack account, as <team ID>/<user ID>"}}},
      "Me": {"allOf": [{"$ref": "#/components/schemas/Identity"}, {"type": "object", "properties": {"admin": {"type": "boolean"}}}]},
      "Requestable": {"type": "object", "properties": {
        "workflow_id": {"type": "string"}, "workflow_name": {"type": "string"}, "description": {"type": "string"},
        "attribute": {"type": "string", "description": "The posture attribute an approval sets on your device; empty if the flow grants groups only", "example": "custom:jit_db_ro"},
        "okta_groups": {"type": "array", "description": "Okta groups an approval adds the requester to until the access ends", "items": {"type": "object", "properties": {"id": {"type": "string", "example": "00g1abcdEFGHijkl2345"}, "name": {"type": "string", "example": "AWS-Prod-Admin"}}}},
        "google_groups": {"type": "array", "description": "Google groups an approval adds the requester to until the access ends", "items": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string", "example": "aws-admin@example.com"}}}},
        "resources": {"type": "array", "items": {"$ref": "#/components/schemas/Resource"}, "description": "Gives access to: what the policy unlocks for the attribute, as described by the admin"},
        "policy": {"$ref": "#/components/schemas/PolicyUse"},
        "max_duration": {"$ref": "#/components/schemas/Duration"}, "default_duration": {"$ref": "#/components/schemas/Duration"},
        "approvers": {"type": "array", "items": {"$ref": "#/components/schemas/Principal"}},
        "allow_self_approval": {"type": "boolean"}, "approvals_required": {"type": "integer"},
        "auto_approve": {"type": "boolean", "description": "Requests are granted at once, with no approver"},
        "active_request_id": {"type": "string", "description": "The caller's live request through this flow, if any"},
        "active_request_url": {"type": "string"}, "active_status": {"$ref": "#/components/schemas/Status"},
        "active_expires_at": {"type": "string", "format": "date-time"}}},
      "NewRequest": {"type": "object", "required": ["workflow_id", "reason"], "properties": {
        "workflow_id": {"type": "string"},
        "duration": {"$ref": "#/components/schemas/Duration"},
        "reason": {"type": "string", "description": "What you need to do and why; shown to the approver"},
        "start_at": {"type": "string", "format": "date-time", "description": "Schedule the access for later (RFC 3339, at most 30 days ahead). Approvers can decide any time before; access starts then, for duration. Omit (or give a time within a minute of now) to start on approval"}}},
      "Approval": {"type": "object", "properties": {"actor": {"type": "string"}, "device_id": {"type": "string", "description": "The approver's device; tells tagged approvers apart"}, "note": {"type": "string"}, "via": {"type": "string", "enum": ["slack"]}, "slack_user": {"type": "string", "description": "With via slack: the Slack account, as <team ID>/<user ID>"}, "at": {"type": "string", "format": "date-time"}}},
      "Enforcement": {"type": "object", "description": "What was verified on the device, separate from what was requested", "properties": {
        "confirmed_at": {"type": "string", "format": "date-time", "description": "The attribute was read back present after approval"},
        "removed_at": {"type": "string", "format": "date-time", "description": "The attribute was read back absent after expiry or revoke"},
        "checked_at": {"type": "string", "format": "date-time"}, "error": {"type": "string"}}},
      "Event": {"type": "object", "properties": {
        "type": {"type": "string", "enum": ["submitted", "approval", "approved", "approve_failed", "started", "start_failed", "declined", "cancelled", "revoked", "revoke_failed", "expired"]},
        "actor": {"type": "string"}, "note": {"type": "string"}, "via": {"type": "string", "enum": ["slack"], "description": "The actor acted from Slack"}, "slack_user": {"type": "string", "description": "With via slack: the Slack account, as <team ID>/<user ID>"}, "at": {"type": "string", "format": "date-time"}}},
      "AccessRequest": {"type": "object", "properties": {
        "id": {"type": "string", "example": "req_ec77cc3939cd0d5d"}, "url": {"type": "string", "description": "The approval page; show this to the user"},
        "workflow_id": {"type": "string"}, "workflow_name": {"type": "string"},
        "attribute": {"type": "string", "example": "custom:jit_db_ro"},
        "okta_groups": {"type": "array", "description": "Okta groups an approval adds the requester to until the access ends", "items": {"type": "object", "properties": {"id": {"type": "string", "example": "00g1abcdEFGHijkl2345"}, "name": {"type": "string", "example": "AWS-Prod-Admin"}}}},
        "google_groups": {"type": "array", "description": "Google groups an approval adds the requester to until the access ends", "items": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string", "example": "aws-admin@example.com"}}}},
        "resources": {"type": "array", "items": {"$ref": "#/components/schemas/Resource"}},
        "requester": {"$ref": "#/components/schemas/Identity"}, "target_device_id": {"type": "string"},
        "duration": {"$ref": "#/components/schemas/Duration"}, "reason": {"type": "string"},
        "start_at": {"type": "string", "format": "date-time", "description": "When access starts, for a scheduled request; absent means on approval"},
        "status": {"$ref": "#/components/schemas/Status"},
        "approvals": {"type": "array", "items": {"$ref": "#/components/schemas/Approval"}}, "approvals_required": {"type": "integer"},
        "approvals_counted": {"type": "integer", "description": "how many of approvals still count under the flow as it is now (pending requests); otherwise every vote cast"},
        "enforcement": {"$ref": "#/components/schemas/Enforcement"},
        "timeline": {"type": "array", "items": {"$ref": "#/components/schemas/Event"}},
        "approved_at": {"type": "string", "format": "date-time"}, "expires_at": {"type": "string", "format": "date-time"},
        "attributes": {"type": "array", "items": {"type": "string"}, "description": "The attribute, once approval set it; empty if access was never granted", "example": ["custom:jit_db_ro"]},
        "policy": {"$ref": "#/components/schemas/PolicyUse"},
        "slack": {"type": "array", "description": "Slack messages posted about the request", "items": {"type": "object", "properties": {"channel": {"type": "string"}, "ts": {"type": "string"}, "kind": {"type": "string", "enum": ["channel", "dm"]}, "user": {"type": "string"}}}},
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
      "Workflow": {"type": "object", "required": ["name", "requesters"], "properties": {
        "id": {"type": "string", "readOnly": true}, "name": {"type": "string", "example": "Database access (read-only)"}, "description": {"type": "string"},
        "attribute": {"type": "string", "description": "custom:jit_<name>; the prefix may be omitted when writing. Optional when okta_groups or google_groups is set", "example": "custom:jit_db_ro"},
        "okta_groups": {"type": "array", "description": "Okta groups an approval adds the requester to until the access ends. When writing, give each by id or by exact name", "items": {"type": "object", "properties": {"id": {"type": "string", "example": "00g1abcdEFGHijkl2345"}, "name": {"type": "string", "example": "AWS-Prod-Admin"}}}},
        "google_groups": {"type": "array", "description": "Google groups an approval adds the requester to until the access ends. When writing, give each by its email address as name", "items": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string", "example": "aws-admin@example.com"}}}},
        "resources": {"type": "array", "items": {"$ref": "#/components/schemas/Resource"}},
        "requesters": {"type": "array", "items": {"$ref": "#/components/schemas/Principal"}},
        "approvers": {"type": "array", "items": {"$ref": "#/components/schemas/Principal"}},
        "allow_self_approval": {"type": "boolean"}, "approvals_required": {"type": "integer", "default": 1, "minimum": 1, "maximum": 10},
        "auto_approve": {"type": "boolean", "description": "Grant every request as soon as it is submitted, with no approver. approvers is then optional; anyone listed may still revoke"},
        "auto_approve_by": {"type": "string", "readOnly": true, "description": "Who made the flow automatic"},
        "auto_approve_at": {"type": "string", "format": "date-time", "readOnly": true},
        "updated_by": {"type": "string", "readOnly": true, "description": "Who saved the flow last"},
        "max_duration": {"allOf": [{"$ref": "#/components/schemas/Duration"}], "description": "1 minute to 365 days"},
        "default_duration": {"allOf": [{"$ref": "#/components/schemas/Duration"}], "description": "At most max_duration"},
        "approval_timeout": {"allOf": [{"$ref": "#/components/schemas/Duration"}], "description": "1 minute to 365 days; pending requests expire after this"}, "disabled": {"type": "boolean"},
        "slack": {"$ref": "#/components/schemas/WorkflowSlack"},
        "created_at": {"type": "string", "format": "date-time", "readOnly": true}, "updated_at": {"type": "string", "format": "date-time", "readOnly": true}}},
      "ErrorBody": {"type": "object", "properties": {"error": {"type": "object", "properties": {
        "code": {"type": "string", "enum": ["bad_request", "forbidden", "not_found", "conflict", "identity_unavailable", "tailscale_api_error", "slack_error", "internal"]},
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
