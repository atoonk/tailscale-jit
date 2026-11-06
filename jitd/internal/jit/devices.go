package jit

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// DeviceOwners returns the logins (lowercased) that own at least one
// untagged, authorized device: the people on the tailnet.
func (s *Service) DeviceOwners(ctx context.Context) (map[string]bool, error) {
	l, ok := s.TS.(tsapi.DeviceLister)
	if !ok {
		return nil, errors.New("jitd's Tailscale API client cannot list devices")
	}
	all, err := l.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, d := range all {
		if d.NodeID != "" && d.Authorized && len(d.Tags) == 0 && d.User != "" {
			out[strings.ToLower(d.User)] = true
		}
	}
	return out, nil
}

// UserDevices lists login's own devices: untagged, authorized and owned by
// login. These are the only devices a request filed outside the browser
// (where WhoIs names the device) may be for. Most recently seen first.
func (s *Service) UserDevices(ctx context.Context, login string) ([]tsapi.Device, error) {
	l, ok := s.TS.(tsapi.DeviceLister)
	if !ok {
		return nil, errors.New("jitd's Tailscale API client cannot list devices")
	}
	all, err := l.ListDevices(ctx)
	if err != nil {
		var ae *tsapi.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusForbidden {
			return nil, errors.New("jitd's Tailscale credential may not list devices; give its OAuth client the devices:core (read) scope")
		}
		return nil, err
	}
	var out []tsapi.Device
	for _, d := range all {
		if d.NodeID != "" && d.Authorized && len(d.Tags) == 0 && strings.EqualFold(d.User, login) {
			out = append(out, d)
		}
	}
	slices.SortStableFunc(out, func(a, b tsapi.Device) int {
		return cmp.Or(b.LastSeen.Compare(a.LastSeen), strings.Compare(a.Name, b.Name))
	})
	return out, nil
}
