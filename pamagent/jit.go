package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// jitClient talks to the jitd access-request service over the tailnet.
// jitd identifies the caller with Tailscale WhoIs, so no credentials are sent.
type jitClient struct {
	base string
	hc   *http.Client
}

// source is the subset of *local.Client used here, so tests can substitute it.
type source interface {
	StatusWithoutPeers(context.Context) (*ipnstate.Status, error)
	GetServices(context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error)
}

// The types mirror the parts of jitd's request JSON that wait reads.

type resource struct {
	Name string `json:"name"`
}

// policyUse is jitd's check of a flow's attribute against the tailnet policy.
type policyUse struct {
	Grants []string `json:"grants"`
	Error  string   `json:"error,omitempty"`
}

// known reports whether the policy was read.
func (p *policyUse) known() bool { return p != nil && p.Error == "" }

type accessRequest struct {
	ID        string     `json:"id"`
	URL       string     `json:"url"`
	Status    string     `json:"status"`
	Resources []resource `json:"resources"`
	Policy    *policyUse `json:"policy,omitempty"`
}

// services are the Tailscale Services approval should make visible on this
// node: what the policy grants when jitd could read it, else the admin's
// list. Tags, hosts and CIDRs cannot be checked locally and are left out.
func (r *accessRequest) services() []string {
	names := resourceNames(r.Resources)
	if r.Policy.known() {
		names = r.Policy.Grants
	}
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "svc:") {
			out = append(out, n)
		}
	}
	return out
}

// resourceNames lists the resource names.
func resourceNames(rs []resource) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

// do calls jitd and decodes its JSON or its {"error":{code,message}} envelope.
func (c *jitClient) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.base, "/")+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("jitd_unavailable: could not reach jitd at %s (is this machine on the tailnet, and may it reach tag:jit? Setting up jitd: %s/tree/main/jitd): %w", c.base, repoURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error.Code != "" {
			return fmt.Errorf("jitd_%s: %s", e.Error.Code, e.Error.Message)
		}
		return fmt.Errorf("jitd_error: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("jitd_error: decoding response: %w", err)
	}
	return nil
}

func (c *jitClient) getRequest(ctx context.Context, id string) (accessRequest, error) {
	var r accessRequest
	err := c.do(ctx, http.MethodGet, "/v1/requests/"+url.PathEscape(id), &r)
	return r, err
}

// backoff is how long wait sleeps between checks, given how long it has been
// waiting: every 3 seconds for the first two minutes (someone is probably
// approving right now, and a check costs jitd next to nothing), every 20
// seconds until 10 minutes, then every minute.
func backoff(waited time.Duration) time.Duration {
	switch {
	case waited < 2*time.Minute:
		return 3 * time.Second
	case waited < 10*time.Minute:
		return 20 * time.Second
	}
	return time.Minute
}

// Exit codes of "pamagent wait".
const (
	waitApproved     = 0
	waitDenied       = 1 // declined, cancelled, revoked or expired
	waitError        = 2
	waitStillPending = 3 // gave up waiting; the request is still open
)

// waitForRequest polls jitd until the request leaves "pending", sleeping
// sched(time waited so far) between checks; ctx bounds that wait. If it was
// approved and src is set, it then waits up to visibleWithin until the local
// tailscaled lists the Tailscale Services in want (the ones the agent needs),
// or, with want empty, any of the services the approval should expose. That
// part is bounded by sig (signals only), not ctx, so a late approval is not
// cut short. It writes one line per change and returns the process exit code
// (see waitApproved and friends).
func waitForRequest(ctx, sig context.Context, c *jitClient, src source, id string, want []string, sched func(time.Duration) time.Duration, visibleWithin time.Duration, w io.Writer) int {
	last := ""
	start := time.Now()
	gaveUp := func() int {
		if last == "pending" {
			fmt.Fprintf(w, "%s still pending after %s; stopped waiting. The request is still open: show the user the link again and run wait again to keep waiting.\n", stamp(), time.Since(start).Round(time.Second))
			return waitStillPending
		}
		fmt.Fprintf(w, "%s timeout: request %s still %s\n", stamp(), id, orUnknown(last))
		return waitError
	}
	for {
		r, err := c.getRequest(ctx, id)
		switch {
		case err != nil && ctx.Err() != nil:
			return gaveUp()
		case err != nil:
			fmt.Fprintf(w, "%s error: %v\n", stamp(), err)
			if strings.HasPrefix(err.Error(), "jitd_not_found") {
				return waitError
			}
		case r.Status != last:
			last = r.Status
			fmt.Fprintf(w, "%s %s %s %s\n", stamp(), r.ID, r.Status, r.URL)
		}
		switch last {
		case "approved":
			if src == nil {
				return waitApproved
			}
			return waitVisible(sig, src, r.services(), want, visibleWithin, w)
		case "declined", "cancelled", "revoked", "expired":
			return waitDenied
		}
		select {
		case <-ctx.Done():
			return gaveUp()
		case <-time.After(sched(time.Since(start))):
		}
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// waitVisible waits until the local tailscaled lists every service in want,
// or, with want empty, at least one of granted (one host being offline must
// not hold up the others). It reports what is visible and what is not yet.
func waitVisible(ctx context.Context, src source, granted, want []string, within time.Duration, w io.Writer) int {
	all := len(want) > 0
	if !all {
		want = granted
	}
	if len(want) == 0 {
		// Nothing the local node can confirm (tags, hosts, or no list):
		// approval is all we can report.
		fmt.Fprintf(w, "%s approved; no Tailscale Services to look for, so visibility cannot be checked here\n", stamp())
		return waitApproved
	}
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	for {
		m, err := src.GetServices(ctx)
		var seen, missing []string
		if err == nil {
			seen, missing = splitVisible(m, want)
		}
		if len(missing) == 0 || (!all && len(seen) > 0) {
			fmt.Fprintf(w, "%s visible: %s", stamp(), strings.Join(seen, ", "))
			if len(missing) > 0 {
				fmt.Fprintf(w, "; not visible yet: %s", strings.Join(missing, ", "))
			}
			fmt.Fprintln(w)
			return waitApproved
		}
		select {
		case <-ctx.Done():
			// Still exit 0: the request is approved; the line says the rest.
			if missing == nil {
				missing = want
			}
			fmt.Fprintf(w, "%s approved, but not visible to this node yet: %s\n", stamp(), strings.Join(missing, ", "))
			return waitApproved
		case <-time.After(time.Second):
		}
	}
}

// splitVisible splits services into the ones m lists and the rest.
func splitVisible(m map[tailcfg.ServiceName]tailcfg.ServiceDetails, services []string) (seen, missing []string) {
	for _, s := range services {
		if _, ok := m[tailcfg.ServiceName(s)]; ok {
			seen = append(seen, s)
		} else {
			missing = append(missing, s)
		}
	}
	return seen, missing
}

func stamp() string { return time.Now().UTC().Format("15:04:05") }
