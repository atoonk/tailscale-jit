// Package slackbot is jitd's Slack integration: it announces access requests
// in Slack, lets approvers approve or decline from the message, and answers
// /jit. Slack is only another way in: every decision goes through the same
// jit.Service methods, with the same rules, as one made in the browser. The
// one new thing is identity: a Slack user is matched to a Tailscale login by
// their Slack email, and every decision made that way is recorded as "via
// Slack".
package slackbot

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
)

// settingKey is where the connection is kept in the store's settings.
const settingKey = "slack"

// Env variables that set the connection from the env file instead of the
// admin page, for people who manage secrets outside jitd.
const (
	EnvBotToken = "SLACK_BOT_TOKEN"
	EnvAppToken = "SLACK_APP_TOKEN"
	EnvDomains  = "SLACK_ALLOWED_DOMAINS" // comma-separated
)

// Settings is the Slack connection. The tokens never leave jitd: the API
// and the pages only ever show their last four characters.
type Settings struct {
	BotToken string `json:"bot_token"` // xoxb-…
	AppToken string `json:"app_token"` // xapp-…, for Socket Mode
	// AllowedDomains are the email domains a Slack user's email must be in
	// to be matched to a Tailscale login, e.g. "example.com".
	AllowedDomains []string  `json:"allowed_domains"`
	TeamID         string    `json:"team_id,omitempty"`
	TeamName       string    `json:"team_name,omitempty"`
	TeamURL        string    `json:"team_url,omitempty"`
	BotUserID      string    `json:"bot_user_id,omitempty"`
	BotName        string    `json:"bot_name,omitempty"`
	ConnectedBy    string    `json:"connected_by,omitempty"`
	ConnectedAt    time.Time `json:"connected_at,omitzero"`
}

func (s Settings) configured() bool { return s.BotToken != "" && s.AppToken != "" }

// Status is what the admin page and GET /v1/slack show.
type Status struct {
	// Source is where the tokens come from: "ui" (saved on the Slack page),
	// "env" (the env file or environment) or "" (not set up).
	Source         string    `json:"source"`
	EnvFile        string    `json:"env_file,omitempty"`
	State          string    `json:"state"` // off, connecting, connected, error
	Since          time.Time `json:"since,omitzero"`
	LastError      string    `json:"last_error,omitempty"`
	TeamName       string    `json:"team_name,omitempty"`
	TeamURL        string    `json:"team_url,omitempty"`
	BotName        string    `json:"bot_name,omitempty"`
	BotTokenHint   string    `json:"bot_token_hint,omitempty"` // "…a1b2"
	AppTokenHint   string    `json:"app_token_hint,omitempty"`
	AllowedDomains []string  `json:"allowed_domains"`
	ConnectedBy    string    `json:"connected_by,omitempty"`
	ConnectedAt    time.Time `json:"connected_at,omitzero"`
	// ManifestURL creates the Slack app with everything jitd needs.
	ManifestURL string `json:"manifest_url"`
}

// Connected reports whether the socket is up.
func (s Status) Connected() bool { return s.State == "connected" }

// Configured reports whether there are tokens.
func (s Status) Configured() bool { return s.Source != "" }

// hint shows the last four characters of a token.
func hint(tok string) string {
	if len(tok) < 8 {
		return ""
	}
	return "…" + tok[len(tok)-4:]
}

// envSettings reads the Slack variables from the env file, then the
// environment for anything the file lacks.
func envSettings(file string) (Settings, error) {
	vars := map[string]string{}
	if file != "" {
		m, err := setup.ReadEnvFile(file)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Settings{}, err
		}
		for _, k := range []string{EnvBotToken, EnvAppToken, EnvDomains} {
			if m[k] != "" {
				vars[k] = m[k]
			}
		}
	}
	for _, k := range []string{EnvBotToken, EnvAppToken, EnvDomains} {
		if vars[k] == "" {
			vars[k] = os.Getenv(k)
		}
	}
	return Settings{
		BotToken:       vars[EnvBotToken],
		AppToken:       vars[EnvAppToken],
		AllowedDomains: CleanDomains(strings.Split(vars[EnvDomains], ",")),
	}, nil
}

// CleanDomains lower-cases, trims and de-duplicates email domains, dropping
// a leading "@".
func CleanDomains(in []string) []string {
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// validDomains checks email domains for the allow list.
func validDomains(ds []string) error {
	if len(ds) == 0 {
		return fmt.Errorf("add at least one email domain (the part after @ in your people's Slack emails)")
	}
	for _, d := range ds {
		if strings.ContainsAny(d, " @/,") || !strings.Contains(d, ".") {
			return fmt.Errorf("invalid email domain %q: use e.g. example.com", d)
		}
	}
	return nil
}

// emailDomain returns the part after the @.
func emailDomain(email string) string {
	_, d, _ := strings.Cut(strings.ToLower(email), "@")
	return d
}

// teamDomain turns https://acme.slack.com/ into acme.slack.com.
func teamDomain(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Host
}
