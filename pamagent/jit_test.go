package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// fakeJITD serves the part of jitd's API that wait uses.
type fakeJITD struct {
	mu       sync.Mutex
	statuses []string // successive statuses returned by GET /v1/requests/{id}
}

func (f *fakeJITD) request(status string) string {
	return `{"id":"req_1","url":"http://jit.example/requests/req_1","workflow_id":"wf_ro","workflow_name":"Database access (read-only)",
	 "attribute":"custom:jit_db_ro","resources":[{"name":"svc:db1","description":"Orders MySQL"},{"name":"svc:db2"}],"status":"` + status + `","duration":"15m0s","reason":"look",
	 "requester":{"login":"alice@example.com","device_id":"nA"},"target_device_id":"nA","expires_at":"2026-10-01T12:15:00Z",
	 "timeline":[{"type":"submitted","actor":"alice@example.com","at":"2026-10-01T12:00:00Z"}]}`
}

func (f *fakeJITD) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "req_1" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":{"code":"not_found","message":"access request not found"}}`)
			return
		}
		f.mu.Lock()
		st := "pending"
		if len(f.statuses) > 0 {
			st = f.statuses[0]
			if len(f.statuses) > 1 {
				f.statuses = f.statuses[1:]
			}
		}
		f.mu.Unlock()
		io.WriteString(w, f.request(st))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fakeServices is a source whose visible services can change during a test.
type fakeServices struct {
	mu      sync.Mutex
	visible map[tailcfg.ServiceName]tailcfg.ServiceDetails
}

func (f *fakeServices) StatusWithoutPeers(context.Context) (*ipnstate.Status, error) {
	return &ipnstate.Status{}, nil
}

func (f *fakeServices) GetServices(context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.visible, nil
}

func TestWaitForRequest(t *testing.T) {
	visible := map[tailcfg.ServiceName]tailcfg.ServiceDetails{"svc:db1": {}, "svc:db2": {}}
	for _, tc := range []struct {
		name     string
		statuses []string
		id       string
		timeout  time.Duration
		want     int
		wantOut  []string
	}{
		{"approved and visible", []string{"pending", "pending", "approved"}, "req_1", 5 * time.Second, 0, []string{"req_1 pending", "req_1 approved", "visible: svc:db1, svc:db2"}},
		{"declined", []string{"pending", "declined"}, "req_1", 5 * time.Second, 1, []string{"req_1 declined"}},
		{"cancelled", []string{"pending", "cancelled"}, "req_1", 5 * time.Second, 1, []string{"req_1 cancelled"}},
		{"still pending", []string{"pending"}, "req_1", 300 * time.Millisecond, 3, []string{"still pending after", "run wait again"}},
		{"unknown request", nil, "req_x", 5 * time.Second, 2, []string{"jitd_not_found"}},
	} {
		f := &fakeJITD{statuses: tc.statuses}
		srv := f.start(t)
		c := &jitClient{base: srv.URL, hc: srv.Client()}
		ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
		var out bytes.Buffer
		got := waitForRequest(ctx, context.Background(), c, &fakeServices{visible: visible}, tc.id, nil, func(time.Duration) time.Duration { return 10 * time.Millisecond }, time.Second, &out)
		cancel()
		if got != tc.want {
			t.Errorf("%s: exit %d, want %d\n%s", tc.name, got, tc.want, out.String())
		}
		for _, w := range tc.wantOut {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%s: output missing %q:\n%s", tc.name, w, out.String())
			}
		}
	}
}

func TestJITUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c := &jitClient{base: url, hc: &http.Client{Timeout: time.Second}}
	_, err := c.getRequest(context.Background(), "req_1")
	if err == nil || !strings.HasPrefix(err.Error(), "jitd_unavailable") {
		t.Errorf("unreachable jitd: %v", err)
	}
}

func TestBackoff(t *testing.T) {
	for _, tc := range []struct{ waited, want time.Duration }{
		{0, 3 * time.Second}, {time.Minute, 3 * time.Second}, {119 * time.Second, 3 * time.Second},
		{2 * time.Minute, 20 * time.Second}, {4 * time.Minute, 20 * time.Second},
		{10 * time.Minute, time.Minute}, {30 * time.Minute, time.Minute},
	} {
		if got := backoff(tc.waited); got != tc.want {
			t.Errorf("backoff(%v) = %v, want %v", tc.waited, got, tc.want)
		}
	}
	// With the 5-minute default: checks at 0, 3s ... 2m (41), then every
	// 20s until 5m (9 more).
	n, at := 0, time.Duration(0)
	for at <= 5*time.Minute {
		n++
		at += backoff(at)
	}
	if n != 50 {
		t.Errorf("%d checks in 5 minutes, want 50", n)
	}
}

func TestRequestServices(t *testing.T) {
	r := accessRequest{Resources: []resource{{Name: "svc:listed"}, {Name: "tag:x"}}}
	if got := fmt.Sprint(r.services()); got != "[svc:listed]" {
		t.Errorf("without policy: %s", got)
	}
	r.Policy = &policyUse{Grants: []string{"svc:granted", "tag:y"}}
	if got := fmt.Sprint(r.services()); got != "[svc:granted]" {
		t.Errorf("with policy: %s", got)
	}
	r.Policy = &policyUse{Error: "403"}
	if got := fmt.Sprint(r.services()); got != "[svc:listed]" {
		t.Errorf("unreadable policy falls back to the list: %s", got)
	}
}

// Visibility waiting outlives the overall timeout: a request approved just
// before the deadline still waits for its services (bounded by sig only).
func TestWaitVisibilityOutlivesTimeout(t *testing.T) {
	f := &fakeJITD{statuses: []string{"approved"}}
	srv := f.start(t)
	c := &jitClient{base: srv.URL, hc: srv.Client()}
	src := &fakeServices{}
	go func() {
		time.Sleep(150 * time.Millisecond) // after ctx below has expired
		src.mu.Lock()
		src.visible = map[tailcfg.ServiceName]tailcfg.ServiceDetails{"svc:db1": {}, "svc:db2": {}}
		src.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	got := waitForRequest(ctx, context.Background(), c, src, "req_1", nil, func(time.Duration) time.Duration { return 10 * time.Millisecond }, 5*time.Second, &out)
	if got != waitApproved || !strings.Contains(out.String(), "visible: svc:db1, svc:db2") {
		t.Errorf("exit %d\n%s", got, out.String())
	}
}

// After approval, wait settles for the services the agent needs (or, without
// -service, any granted one) instead of waiting for every service the flow
// covers: one offline host must not hold it up for a minute.
func TestWaitVisiblePartial(t *testing.T) {
	src := &fakeServices{visible: map[tailcfg.ServiceName]tailcfg.ServiceDetails{"svc:db1": {}}}
	granted := []string{"svc:db1", "svc:db2"}
	for _, tc := range []struct {
		name    string
		want    []string
		within  time.Duration
		maxTime time.Duration
		out     string
	}{
		{"any granted", nil, 5 * time.Second, time.Second, "visible: svc:db1; not visible yet: svc:db2"},
		{"the one needed", []string{"svc:db1"}, 5 * time.Second, time.Second, "visible: svc:db1\n"},
		{"needed but missing", []string{"svc:db2"}, 1500 * time.Millisecond, 3 * time.Second, "not visible to this node yet: svc:db2"},
	} {
		var out bytes.Buffer
		start := time.Now()
		got := waitVisible(context.Background(), src, granted, tc.want, tc.within, &out)
		if took := time.Since(start); got != waitApproved || took > tc.maxTime || !strings.Contains(out.String(), tc.out) {
			t.Errorf("%s: exit %d after %v\n%s", tc.name, got, took, out.String())
		}
	}
}

func TestServiceNames(t *testing.T) {
	got := serviceNames(" svc:server01, bastion03 ,,")
	if want := []string{"svc:server01", "svc:bastion03"}; !slices.Equal(got, want) {
		t.Errorf("serviceNames = %q, want %q", got, want)
	}
	if got := serviceNames(""); got != nil {
		t.Errorf("serviceNames(\"\") = %q, want nil", got)
	}
}
