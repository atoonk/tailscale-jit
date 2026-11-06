package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Conn is one WebSocket connection, as the Socket needs it.
type Conn interface {
	Read(ctx context.Context) ([]byte, error)
	Write(ctx context.Context, b []byte) error
	Close() error
}

// Dialer opens a WebSocket to url.
type Dialer func(ctx context.Context, url string) (Conn, error)

// DialWebSocket is the real Dialer.
func DialWebSocket(ctx context.Context, url string) (Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(dctx, url, nil)
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(4 << 20)
	return &wsConn{c}, nil
}

type wsConn struct{ c *websocket.Conn }

func (w *wsConn) Read(ctx context.Context) ([]byte, error) {
	_, b, err := w.c.Read(ctx)
	return b, err
}
func (w *wsConn) Write(ctx context.Context, b []byte) error {
	return w.c.Write(ctx, websocket.MessageText, b)
}
func (w *wsConn) Close() error { return w.c.Close(websocket.StatusNormalClosure, "bye") }

// Handler handles one Socket Mode envelope. For a slash command or a
// submitted modal its return value, if any, goes back to Slack in the ack
// (the reply, or validation errors); it then has to return within the ack
// deadline. For anything else the ack has already gone and the return
// value is ignored.
type Handler func(ctx context.Context, env Envelope) any

// Socket keeps one Socket Mode connection open: it asks for a URL, dials,
// acks every envelope and hands it to the handler, and reconnects with
// backoff when the connection ends or Slack asks it to.
type Socket struct {
	API  API
	Dial Dialer // DialWebSocket if nil
	// Handle is called for every envelope but hello and disconnect.
	Handle Handler
	// Logf gets connection events; may be nil.
	Logf func(format string, args ...any)

	mu     sync.Mutex
	status Status
}

// Status is the connection's state, for the admin page.
type Status struct {
	State     string    `json:"state"` // "off", "connecting", "connected", "error"
	Since     time.Time `json:"since"`
	LastError string    `json:"last_error,omitempty"`
}

type ackKey struct{}

// Acked returns a channel that is closed once the ack for the envelope that
// ctx was handed with has been written. Work a handler starts in the
// background and that updates what the ack shows (a modal the ack
// replaced) waits for it, so the two arrive at Slack in order. Outside a
// handler, it is closed already.
func Acked(ctx context.Context) <-chan struct{} {
	if c, ok := ctx.Value(ackKey{}).(chan struct{}); ok {
		return c
	}
	c := make(chan struct{})
	close(c)
	return c
}

// ackDeadline is how long Slack waits for an ack before it retries.
const ackDeadline = 3 * time.Second

// Status returns the connection's state.
func (s *Socket) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Socket) setState(state, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State != state {
		s.status.Since = time.Now()
	}
	s.status.State = state
	if lastErr != "" || state == "connected" {
		s.status.LastError = lastErr
	}
}

func (s *Socket) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Run connects and serves until ctx ends.
func (s *Socket) Run(ctx context.Context) {
	defer s.setState("off", "")
	wait := time.Second
	for {
		s.setState("connecting", "")
		err := s.serveOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.setState("error", err.Error())
			s.logf("slack socket: %v; reconnecting in %s", err, wait)
		} else {
			// Slack asked for a fresh connection (it refreshes them every
			// few hours): reconnect at once.
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, time.Minute)
	}
}

// serveOnce runs one connection to its end. It returns nil when Slack asked
// for a reconnect, the error otherwise.
func (s *Socket) serveOnce(ctx context.Context) error {
	url, err := s.API.ConnectionsOpen(ctx)
	if err != nil {
		return err
	}
	dial := s.Dial
	if dial == nil {
		dial = DialWebSocket
	}
	conn, err := dial(ctx, url)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	// Writes from the handlers' acks and the reader must not interleave.
	var wmu sync.Mutex
	write := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		wmu.Lock()
		defer wmu.Unlock()
		return conn.Write(wctx, b)
	}
	for {
		b, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		var env Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			s.logf("slack socket: bad frame: %v", err)
			continue
		}
		switch env.Type {
		case "hello":
			s.setState("connected", "")
			s.logf("slack socket: connected")
			continue
		case "disconnect":
			s.logf("slack socket: slack asked to reconnect (%s)", env.Reason)
			return nil
		}
		if env.EnvelopeID == "" {
			continue
		}
		ack := map[string]any{"envelope_id": env.EnvelopeID}
		if env.AcceptsResponsePayload && (env.Type == "slash_commands" || isViewSubmission(env)) {
			// The reply rides in the ack, so the handler runs first, within
			// Slack's deadline. It must be quick: it holds up this reader.
			// Slow work goes in the background and waits for Acked.
			acked := make(chan struct{})
			hctx, cancel := context.WithTimeout(context.WithValue(ctx, ackKey{}, acked), ackDeadline-500*time.Millisecond)
			if payload := s.handle(hctx, env); payload != nil {
				ack["payload"] = payload
			}
			cancel()
			err := write(ack)
			close(acked)
			if err != nil {
				return fmt.Errorf("ack: %w", err)
			}
			continue
		}
		if err := write(ack); err != nil {
			return fmt.Errorf("ack: %w", err)
		}
		go s.handle(context.WithoutCancel(ctx), env)
	}
}

func isViewSubmission(env Envelope) bool {
	if env.Type != "interactive" {
		return false
	}
	var p struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(env.Payload, &p) == nil && p.Type == "view_submission"
}

// handle calls the handler, keeping a panic in it from taking the
// connection down.
func (s *Socket) handle(ctx context.Context, env Envelope) (out any) {
	if s.Handle == nil {
		return nil
	}
	defer func() {
		if p := recover(); p != nil {
			s.logf("slack socket: handler panic: %v", p)
			out = nil
		}
	}()
	return s.Handle(ctx, env)
}

// ErrClosed is returned by a fake connection once it is closed.
var ErrClosed = errors.New("connection closed")
