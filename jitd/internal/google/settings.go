package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Settings are what an admin saved on jitd's Google page. jitd keeps them
// in its database. A value set in the environment or the env file is used
// instead of the one here.
type Settings struct {
	// Key is the service account's JSON key, whole.
	Key string `json:"key"`
	// Domains are the email domains whose users jitd may add to groups.
	Domains []string `json:"domains"`
	// Grant lists the groups approval flows may grant (emails or IDs, * as
	// a wildcard).
	Grant   []string  `json:"grant_allowlist"`
	SavedBy string    `json:"saved_by,omitempty"`
	SavedAt time.Time `json:"saved_at"`
}

// Vars returns the settings as the variables jitd reads.
func (s Settings) Vars() map[string]string {
	return map[string]string{
		EnvKey:            s.Key,
		EnvDomains:        strings.Join(s.Domains, ","),
		EnvGrantAllowlist: strings.Join(s.Grant, ","),
	}
}

// EnableURL is where the Cloud Identity API is switched on for a project.
func EnableURL(project string) string {
	u := "https://console.cloud.google.com/apis/library/cloudidentity.googleapis.com"
	if project != "" {
		u += "?project=" + url.QueryEscape(project)
	}
	return u
}

// RolesURL is where a super admin assigns admin roles.
const RolesURL = "https://admin.google.com/ac/roles"

// Explain says, for the Google page, what a failed try of the key means and
// what to change, in the order an admin meets these: the key, the API, the
// role. key may be nil. fix is empty when there is nothing to advise beyond
// what says.
func Explain(err error, key *Key) (what, fix string) {
	project, account := "", "the service account"
	if key != nil {
		project, account = key.Project, key.Email
	}
	var te *TokenError
	var ae *APIError
	var ue *unreachable
	var ne *NoGroupsError
	switch {
	case err == nil:
		return "", ""
	case errors.As(err, &ne):
		return fmt.Sprintf("Google takes the key, but shows %s none of the groups jitd's flows use (looked for %s).", account, strings.Join(ne.Tried, ", ")),
			"In the Google Admin console (" + RolesURL + "), open Groups Admin, choose Assign service accounts and add " + account +
				". A new role can take a few minutes to apply. If these groups were deleted in Google instead, take them out of the flows."
	case errors.As(err, &te):
		why := strings.TrimSuffix(te.Description, ".")
		switch {
		case te.Code == "invalid_grant" && strings.Contains(strings.ToLower(te.Description), "account not found"):
			return fmt.Sprintf("Google does not know %s (%s). It was deleted, or the key is from another account.", account, why),
				"Create the service account again and a new JSON key for it, and paste that key."
		case te.Code == "invalid_grant":
			return fmt.Sprintf("Google did not accept the key (%s). It was deleted or the service account is disabled; a clock that is minutes off on this host gives the same answer.", why),
				"In the Cloud console, open the service account, check that it is enabled, create a new JSON key under Keys, and paste it."
		case te.Code == "":
			return fmt.Sprintf("Google's sign-in did not answer as expected (HTTP %d).", te.Status), "Check that this host can reach oauth2.googleapis.com directly, not through a proxy that rewrites the answer."
		}
		return fmt.Sprintf("Google refused to sign the service account in (%s: %s).", te.Code, why), ""
	case errors.As(err, &ae):
		why := ae.Message
		if why == "" {
			why = fmt.Sprintf("HTTP %d", ae.Status)
		}
		switch {
		case ae.Disabled():
			return "Google took the key, but the Cloud Identity API is not enabled in the service account's project.",
				"Enable it at " + EnableURL(project) + " and try again in a minute."
		case ae.Status == http.StatusUnauthorized:
			return fmt.Sprintf("Google signed the service account in, then turned its token down (%s).", why),
				"Check that the service account is enabled, then try again."
		case ae.Status == http.StatusForbidden:
			return fmt.Sprintf("Google took the key, but does not let the service account do this (%s).", why),
				"In the Google Admin console (" + RolesURL + "), open Groups Admin, choose Assign service accounts and add " + account + ". A new role can take a few minutes to apply."
		case ae.Status == http.StatusTooManyRequests:
			return "Google is rate limiting jitd right now.", "Wait a minute and try again."
		}
		return fmt.Sprintf("Google answered with an error (%s).", why), ""
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ue):
		return fmt.Sprintf("jitd could not reach Google: %v.", err), "Check that this host can reach oauth2.googleapis.com and cloudidentity.googleapis.com."
	}
	return err.Error(), ""
}
