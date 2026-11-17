package main

import (
	"context"
	"errors"
	"os"
	"time"

	"tailscale.com/tsnet"

	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// nodeKeyTTL is how long a node auth key lives if jitd cannot delete it.
const nodeKeyTTL = 10 * time.Minute

// authKeys is the part of the Tailscale API that federatedNodeKey uses.
type authKeys interface {
	CreateAuthKey(ctx context.Context, tags []string, ttl time.Duration, description string) (tsapi.AuthKey, error)
	DeleteAuthKey(ctx context.Context, id string) error
}

// federatedNodeKey lets jitd's node join the tailnet through the federated
// identity jitd uses for the Tailscale API (TS_OAUTH_CLIENT_ID with
// TS_ID_TOKEN, from the env file or the environment), so it needs no auth
// key either. The federated identity needs the auth_keys scope and tag.
//
// On every start, not only the first, it creates a single-use auth key for
// tag that expires after nodeKeyTTL, hands it to tsnet, and has the node
// advertise tag. tsnet only uses the key when the node has to log in: a new
// node, or one whose node key expired or that was logged out. A running node
// ignores it. Advertising tag every time matters: a tagged node started
// without it asks the control server to drop its tag, which logs it out.
//
// The returned cleanup deletes the key; call it once the node is up. It is
// nil when nothing was done: with TS_AUTHKEY, without a federated identity,
// or with an OAuth client secret (that client is used for the API then).
func federatedNodeKey(ctx context.Context, srv *tsnet.Server, tag string, vars map[string]string, newClient func(map[string]string) (authKeys, error)) (cleanup func(context.Context) error, err error) {
	if vars["TS_AUTHKEY"] != "" || vars["TS_AUTH_KEY"] != "" || tsapi.CredentialKind(vars) != "federated" {
		return nil, nil
	}
	c, err := newClient(vars)
	if err != nil {
		return nil, err
	}
	key, err := c.CreateAuthKey(ctx, []string{tag}, nodeKeyTTL, "jitd node")
	if err != nil {
		return nil, err
	}
	srv.AuthKey = key.Key
	srv.AdvertiseTags = []string{tag}
	return func(ctx context.Context) error { return c.DeleteAuthKey(ctx, key.ID) }, nil
}

// nodeKeyVars returns the variables federatedNodeKey looks at: the Tailscale
// API credentials from the env file, then the environment for anything the
// file lacks, as the Setup page reads them, and TS_AUTHKEY.
func nodeKeyVars(envFile string) (map[string]string, error) {
	vars := map[string]string{}
	if envFile != "" {
		fromFile, err := setup.ReadEnvFile(envFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, k := range tsapi.CredentialVars {
			if v := fromFile[k]; v != "" {
				vars[k] = v
			}
		}
	}
	for _, k := range append(tsapi.CredentialVars, "TS_AUTHKEY", "TS_AUTH_KEY") {
		if vars[k] == "" {
			vars[k] = os.Getenv(k)
		}
	}
	return vars, nil
}
