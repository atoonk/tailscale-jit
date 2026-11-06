package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientWireFormat(t *testing.T) {
	var throttled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/auth.test":
			if auth != "Bearer xoxb-1" {
				io.WriteString(w, `{"ok":false,"error":"invalid_auth"}`)
				return
			}
			io.WriteString(w, `{"ok":true,"team":"Acme","team_id":"T1","user":"jit","user_id":"U1","url":"https://acme.slack.com/"}`)
		case "/apps.connections.open":
			if auth != "Bearer xapp-1" {
				t.Errorf("connections.open with %q", auth)
			}
			io.WriteString(w, `{"ok":true,"url":"wss://x"}`)
		case "/chat.postMessage":
			if !throttled.Swap(true) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("postMessage content type %q", ct)
			}
			var body map[string]any
			json.Unmarshal(b, &body)
			if body["channel"] != "C1" || body["blocks"] == nil {
				t.Errorf("postMessage body %s", b)
			}
			io.WriteString(w, `{"ok":true,"ts":"1.2"}`)
		case "/users.lookupByEmail":
			if !strings.Contains(string(b), "email=sam%40example.com") {
				t.Errorf("lookup body %s", b)
			}
			io.WriteString(w, `{"ok":false,"error":"users_not_found"}`)
		case "/conversations.list":
			if strings.Contains(string(b), "cursor=p2") {
				io.WriteString(w, `{"ok":true,"channels":[{"id":"C2","name":"b"}],"response_metadata":{"next_cursor":""}}`)
				return
			}
			io.WriteString(w, `{"ok":true,"channels":[{"id":"C1","name":"a"}],"response_metadata":{"next_cursor":"p2"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New("xoxb-1", "xapp-1")
	c.BaseURL = srv.URL
	ctx := context.Background()

	a, err := c.AuthTest(ctx)
	if err != nil || a.Team != "Acme" || a.UserID != "U1" {
		t.Fatalf("auth.test = %+v, %v", a, err)
	}
	if u, err := c.ConnectionsOpen(ctx); err != nil || u != "wss://x" {
		t.Fatalf("connections.open = %q, %v", u, err)
	}
	ts, err := c.PostMessage(ctx, "C1", Message{Text: "hi", Blocks: []Block{Section(Mrkdwn("hi"))}})
	if err != nil || ts != "1.2" {
		t.Fatalf("postMessage = %q, %v (after one 429)", ts, err)
	}
	if _, err := c.LookupUserByEmail(ctx, "sam@example.com"); ErrorCode(err) != "users_not_found" {
		t.Fatalf("lookup error = %v", err)
	}
	cs, err := c.ListChannels(ctx)
	if err != nil || len(cs) != 2 || cs[1].ID != "C2" {
		t.Fatalf("channels = %+v, %v", cs, err)
	}
	bad := New("xoxb-wrong", "")
	bad.BaseURL = srv.URL
	if _, err := bad.AuthTest(ctx); ErrorCode(err) != "invalid_auth" {
		t.Fatalf("bad token: %v", err)
	}
}

func TestSocketAcksAndReconnects(t *testing.T) {
	f := NewFake()
	got := make(chan string, 10)
	s := &Socket{API: f, Dial: f.Dial, Handle: func(ctx context.Context, env Envelope) any {
		got <- env.Type
		if env.Type == "slash_commands" {
			return Ephemeral(Message{Text: "hello"})
		}
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	wait := func(what string, cond func() bool) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("timed out: %s", what)
			}
		}
	}
	wait("connected", func() bool { return s.Status().State == "connected" })

	acks := f.Acks()
	f.Send(Interactive("U1", "C1", "1.1", "jit_approve", "req_1"))
	if typ := <-got; typ != "interactive" {
		t.Fatalf("handled %s", typ)
	}
	if b := <-acks; !strings.Contains(string(b), `"envelope_id":"env-jit_approve-1.1"`) {
		t.Fatalf("ack %s", b)
	}
	f.Send(Command("U1", "C1", "/jit", ""))
	<-got
	if b := <-acks; !strings.Contains(string(b), `"payload":{"response_type":"ephemeral","text":"hello"}`) {
		t.Fatalf("command ack %s", b)
	}

	// Slack asks for a reconnect: a new connection is opened.
	b, _ := json.Marshal(map[string]string{"type": "disconnect", "reason": "refresh_requested"})
	f.current().in <- b
	wait("reconnected", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.Opened >= 2 })
	wait("connected again", func() bool { return s.Status().State == "connected" })

	// The connection drops: the socket reports it and comes back.
	f.Drop()
	wait("third connection", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.Opened >= 3 })
	wait("connected after drop", func() bool { return s.Status().State == "connected" })

	cancel()
	<-done
	if st := s.Status().State; st != "off" {
		t.Fatalf("state after stop = %s", st)
	}
}
