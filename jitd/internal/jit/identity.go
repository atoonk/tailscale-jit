package jit

import (
	"cmp"
	"context"
	"net/http"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
)

// Resolver identifies the caller of an HTTP request.
type Resolver interface {
	Resolve(ctx context.Context, r *http.Request) (Identity, error)
}

// ResolverFunc adapts a function to Resolver (used by tests).
type ResolverFunc func(ctx context.Context, r *http.Request) (Identity, error)

func (f ResolverFunc) Resolve(ctx context.Context, r *http.Request) (Identity, error) {
	return f(ctx, r)
}

// WhoIsClient is satisfied by *local.Client (tsnet.Server.LocalClient()).
type WhoIsClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// WhoIsResolver identifies callers by asking tailscaled who owns the
// connection's source address.
type WhoIsResolver struct {
	Client  WhoIsClient
	Timeout time.Duration
}

func (w *WhoIsResolver) Resolve(ctx context.Context, r *http.Request) (Identity, error) {
	if w.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, w.Timeout)
		defer cancel()
	}
	res, err := w.Client.WhoIs(ctx, r.RemoteAddr)
	if err != nil {
		return Identity{}, newErr(http.StatusUnauthorized, "identity_unavailable", "could not identify caller %s via Tailscale WhoIs: %v", r.RemoteAddr, err)
	}
	if res.Node == nil {
		return Identity{}, newErr(http.StatusUnauthorized, "identity_unavailable", "Tailscale WhoIs returned no node for %s", r.RemoteAddr)
	}
	id := Identity{
		DeviceID:   string(res.Node.StableID),
		DeviceName: cmp.Or(res.Node.ComputedName, strings.TrimSuffix(res.Node.Name, ".")),
		Tags:       res.Node.Tags,
	}
	if res.UserProfile != nil {
		id.Login = res.UserProfile.LoginName
		id.DisplayName = res.UserProfile.DisplayName
	}
	return id, nil
}
