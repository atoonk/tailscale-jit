package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMCP answers like jitd's stateless /mcp: JSON for one call, 202 for
// notifications, a refusal for a caller it does not know, and (unlike jitd
// today, which answers plain JSON) an event stream for another call, to
// keep the pass-through path tested. "slow" answers after 5 s unless the
// client goes away first.
func fakeMCP(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json, text/event-stream" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers: %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		json.Unmarshal(body, &m)
		switch {
		case m.Method == "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case m.Method == "initialize":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"jitd"}}}`)
		case m.Method == "tools/call" && m.Params.Name == "wait_for_access":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"p1\",\"message\":\"still waiting\"}}\n\n")
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
			io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":"+string(m.ID)+",\n")
			io.WriteString(w, "data: \"result\":{\"content\":[{\"type\":\"text\",\"text\":\"APPROVED\"}]}}\n\n")
		case m.Method == "tools/call" && m.Params.Name == "slow":
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Second):
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":{"content":[]}}`)
		case m.Method == "tools/call":
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":{"code":"identity_unavailable","message":"unknown caller"}}`)
		default:
			t.Errorf("unexpected message %s", body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// lines collects stdout messages as they are written.
type lines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lines) wait(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		out := strings.Split(strings.TrimSpace(l.buf.String()), "\n")
		l.mu.Unlock()
		if len(out) >= n && out[0] != "" {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d lines, want %d:\n%s", len(out), n, strings.Join(out, "\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBridge(t *testing.T) {
	srv := fakeMCP(t)
	out := &lines{}
	b := &bridge{endpoint: srv.URL + "/mcp", hc: srv.Client(), log: slog.New(slog.NewTextHandler(io.Discard, nil)), out: out}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		"\n" + // blank lines are skipped
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wait_for_access","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"other"}}`) // no trailing newline
	if err := b.run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got := out.wait(t, 4)
	byID := map[string]string{}
	var progress int
	for _, l := range got {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %s", l)
		}
		if m.Method == "notifications/progress" {
			progress++
			continue
		}
		byID[string(m.ID)] = l
	}
	if progress != 1 {
		t.Errorf("progress notifications = %d, want 1:\n%s", progress, strings.Join(got, "\n"))
	}
	if !strings.Contains(byID["1"], `"serverInfo":{"name":"jitd"}`) {
		t.Errorf("initialize reply: %s", byID["1"])
	}
	// The two-line SSE data was joined into one message.
	if !strings.Contains(byID["2"], `"text":"APPROVED"`) {
		t.Errorf("wait reply: %s", byID["2"])
	}
	// jitd's JSON error envelope is unwrapped into a sentence with a next step.
	if !strings.Contains(byID["3"], `"error"`) || !strings.Contains(byID["3"], "could not identify this machine") || !strings.Contains(byID["3"], "unknown caller") || strings.Contains(byID["3"], `{\"error\"`) {
		t.Errorf("refused call: %s", byID["3"])
	}
}

// Closing stdin stops the bridge after a short grace, cancelling a long tool
// call in flight rather than finishing it for a host that has gone.
func TestBridgeStopsOnEOF(t *testing.T) {
	srv := fakeMCP(t)
	out := &lines{}
	b := &bridge{endpoint: srv.URL + "/mcp", hc: srv.Client(), log: slog.New(slog.NewTextHandler(io.Discard, nil)), out: out}
	start := time.Now()
	if err := b.run(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"slow"}}`+"\n")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > eofGrace+1500*time.Millisecond {
		t.Errorf("run took %s after stdin closed; want about %s", d, eofGrace)
	}
}

func TestEndpointFor(t *testing.T) {
	for in, want := range map[string]string{
		"http://jit": "http://jit/mcp", "http://jit/": "http://jit/mcp",
		"http://jit/mcp": "http://jit/mcp", "http://jit/mcp/": "http://jit/mcp",
		"http://jit.example.ts.net:8080": "http://jit.example.ts.net:8080/mcp",
	} {
		if got := endpointFor(in); got != want {
			t.Errorf("endpointFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExplain(t *testing.T) {
	if got := explain(404, []byte("404 page not found"), "http://jit/mcp/mcp"); !strings.Contains(got, "-jit-url is jitd's base URL") {
		t.Errorf("404: %s", got)
	}
	if got := explain(401, []byte(`{"error":{"code":"identity_unavailable","message":"could not identify caller 100.1.2.3:4 via Tailscale WhoIs: no node"}}`), ""); !strings.HasPrefix(got, "jitd could not identify this machine") || !strings.Contains(got, "no node") || strings.Contains(got, "{") {
		t.Errorf("401: %s", got)
	}
	if got := explain(500, []byte("boom"), ""); got != "jitd answered HTTP 500: boom" {
		t.Errorf("500: %s", got)
	}
}

func TestBridgeUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	out := &lines{}
	b := &bridge{endpoint: url + "/mcp", hc: &http.Client{Timeout: time.Second}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), out: out}
	b.run(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`+"\n"))
	got := out.wait(t, 1)
	if !strings.Contains(got[0], `"id":7`) || !strings.Contains(got[0], "could not reach jitd") {
		t.Errorf("reply: %s", got[0])
	}
}
