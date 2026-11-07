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

// fakeMCP answers like jitd's stateless /mcp: JSON for one call, an event
// stream with a progress notification for another, 202 for notifications,
// and refuses a caller it does not know.
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
	if !strings.Contains(byID["3"], `"error"`) || !strings.Contains(byID["3"], "HTTP 401") || !strings.Contains(byID["3"], "identity_unavailable") {
		t.Errorf("refused call: %s", byID["3"])
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
