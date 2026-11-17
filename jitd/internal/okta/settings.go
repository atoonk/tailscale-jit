package okta

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Settings are Okta credentials an admin saved on jitd's Okta page. jitd
// keeps them in its database; the ones in the environment or the env file,
// if any, are used instead.
type Settings struct {
	OrgURL       string    `json:"org_url"`
	ClientID     string    `json:"client_id,omitempty"`
	PrivateKey   string    `json:"private_key,omitempty"`
	PrivateKeyID string    `json:"private_key_id,omitempty"`
	Scopes       string    `json:"scopes,omitempty"`
	APIToken     string    `json:"api_token,omitempty"`
	SavedBy      string    `json:"saved_by,omitempty"`
	SavedAt      time.Time `json:"saved_at"`
}

// Vars returns the settings as the variables NewFromValues reads.
func (s Settings) Vars() map[string]string {
	return map[string]string{
		"OKTA_ORG_URL":        s.OrgURL,
		"OKTA_API_TOKEN":      s.APIToken,
		"OKTA_CLIENT_ID":      s.ClientID,
		"OKTA_PRIVATE_KEY":    s.PrivateKey,
		"OKTA_PRIVATE_KEY_ID": s.PrivateKeyID,
		"OKTA_SCOPES":         s.Scopes,
	}
}

// KeyFingerprint names a PEM private key without giving it away: the start
// of the SHA-256 of its public half. It is empty for a key jitd cannot read.
func KeyFingerprint(pemKey string) string {
	k, _, err := parsePrivateKey(pemKey)
	if err != nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// Explain says, for the Okta page, what a failed try of the credentials
// means and what to change in Okta, in the order an admin meets these: the
// address, the key, DPoP, the scopes, the admin role. serviceApp tells the
// two ways of signing in apart. fix is empty when there is nothing to
// advise beyond what says.
func Explain(err error, serviceApp bool) (what, fix string) {
	const address = "Check the Okta address: it is your org's own, like https://example.okta.com, not the admin console's (the one with -admin in it)."
	var te *TokenError
	var ae *APIError
	var ue *url.Error
	switch {
	case err == nil:
		return "", ""
	case errors.As(err, &te):
		switch {
		case te.DPoP():
			return "Okta wants DPoP proofs from this app, and jitd does not send them.",
				"On the app's General tab, under Client Credentials, turn off \"Require Demonstrating Proof of Possession (DPoP) header in token requests\"."
		case te.Code == "invalid_client":
			return fmt.Sprintf("Okta did not accept the client ID and private key (%s).", strings.TrimSuffix(te.Description, ".")),
				"Check that the client ID is the one on the app's General tab, and that the private key is the one generated for this app (Client Credentials, Public keys). If the app has more than one key, fill in the key ID."
		case te.Code == "invalid_scope":
			return fmt.Sprintf("Okta will not give the app the scopes jitd asks for (%s).", strings.TrimSuffix(te.Description, ".")),
				"On the app's Okta API Scopes tab, grant okta.users.read and okta.groups.manage. If both are granted, give the app its admin role first (Admin roles tab)."
		case te.Code == "":
			return fmt.Sprintf("That address did not answer like an Okta org (its token endpoint returned HTTP %d).", te.Status), address
		}
		return fmt.Sprintf("Okta refused to sign the app in (%s: %s).", te.Code, strings.TrimSuffix(te.Description, ".")), ""
	case errors.As(err, &ae):
		why := ae.Summary
		if why == "" {
			why = fmt.Sprintf("HTTP %d", ae.Status)
		}
		switch ae.Status {
		case http.StatusUnauthorized:
			if serviceApp {
				return fmt.Sprintf("Okta signed the app in, then turned its token down (%s).", why),
					"Check that the app is active in Okta, then try again."
			}
			return fmt.Sprintf("Okta did not accept the API token (%s). It is mistyped, revoked or expired: Okta expires a token that goes unused for 30 days.", why),
				"Create a new token under Security, API, Tokens."
		case http.StatusForbidden:
			if serviceApp {
				return fmt.Sprintf("Okta signed the app in, but does not let it look at groups (%s).", why),
					"Give the app an admin role: on its Admin roles tab, assign Group Administrator (or a custom role with Manage group membership), limited to the groups jitd should manage. A new role can take a minute to apply."
			}
			return fmt.Sprintf("Okta accepted the token, but does not let it look at groups (%s).", why),
				"Give the token's user the Group Administrator role, limited to the groups jitd should manage, and create the token while signed in as that user."
		case http.StatusNotFound:
			return "That address did not answer like an Okta org (its API returned HTTP 404).", address
		case http.StatusTooManyRequests:
			return "Okta is rate limiting jitd right now.", "Wait a minute and try again."
		}
		return fmt.Sprintf("Okta answered with an error (%s).", why), ""
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ue):
		return fmt.Sprintf("jitd could not reach Okta: %v.", err), address + " Check, too, that this host can reach the internet."
	}
	return err.Error(), ""
}
