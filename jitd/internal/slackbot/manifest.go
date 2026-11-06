package slackbot

import (
	"encoding/json"
	"net/url"
)

// AppName is the Slack app's name, and the bot's.
const AppName = "JIT access"

// Scopes are the bot token scopes the app asks for, each for one thing jitd
// does.
var Scopes = []string{
	"chat:write",        // post and update request messages
	"chat:write.public", // post to public channels without being invited
	"commands",          // /jit
	"im:write",          // direct messages to approvers
	"users:read",        // who clicked a button
	"users:read.email",  // their email, to match them to a Tailscale login
	"channels:read",     // the channel picker on the flow form
	"groups:read",       // private channels the bot was invited to
}

// Manifest is the Slack app manifest: a bot with Socket Mode (Slack never
// calls jitd; jitd connects out), buttons and /jit.
func Manifest() map[string]any {
	return map[string]any{
		"_metadata": map[string]int{"major_version": 2, "minor_version": 1},
		"display_information": map[string]string{
			"name":             AppName,
			"description":      "Approve Tailscale just-in-time access requests from Slack",
			"background_color": "#1f1e1e",
		},
		"features": map[string]any{
			"bot_user": map[string]any{"display_name": AppName, "always_online": true},
			"slash_commands": []map[string]any{{
				"command": "/jit", "description": "Request access, and see your requests and the ones waiting for you", "usage_hint": "[request | help]", "should_escape": false,
			}},
		},
		"oauth_config": map[string]any{"scopes": map[string][]string{"bot": Scopes}},
		"settings": map[string]any{
			"interactivity":          map[string]bool{"is_enabled": true},
			"org_deploy_enabled":     false,
			"socket_mode_enabled":    true,
			"token_rotation_enabled": false,
		},
	}
}

// ManifestURL opens Slack's "create an app" page filled in from Manifest.
func ManifestURL() string {
	b, _ := json.Marshal(Manifest())
	return "https://api.slack.com/apps?new_app=1&manifest_json=" + url.QueryEscape(string(b))
}
