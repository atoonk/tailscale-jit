package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// bridge is "pamagent bridge": an MCP server on stdin/stdout that forwards
// every message to jitd's MCP endpoint over the tailnet, for hosts that only
// run local (stdio) servers. jitd's /mcp is stateless, so each message is one
// HTTP POST, answered with one JSON object, which goes back out on stdout.
// An event stream would be passed through too, should a later jitd send
// one. Nothing is interpreted here beyond turning an HTTP refusal into a
// JSON-RPC error: the host and jitd negotiate everything, including the MCP
// Apps view, between themselves.
type bridge struct {
	endpoint string // jitd's /mcp URL
	hc       *http.Client
	log      *slog.Logger
	out      io.Writer
	mu       sync.Mutex // serialises writes to out
}

// run reads messages from in until it ends or ctx is done, handling each in
// its own goroutine so a long tool call (wait_for_access) does not hold up
// pings and other calls.
func (b *bridge) run(ctx context.Context, in io.Reader) error {
	r := bufio.NewReaderSize(in, 1<<20)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		// Closing stdin is how hosts stop a stdio server. Quick answers
		// still in flight get a moment to land (a one-shot
		// `echo ... | pamagent bridge` wants them); a wait_for_access that
		// could run for minutes is cut short rather than finished for nobody.
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(eofGrace):
			cancel()
			<-done
		}
	}()
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			msg := bytes.Clone(bytes.TrimSpace(line))
			wg.Add(1)
			go func() {
				defer wg.Done()
				b.forward(ctx, msg)
			}()
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// eofGrace is how long in-flight calls may finish after stdin closes.
const eofGrace = 2 * time.Second

// forward POSTs one JSON-RPC message to jitd and writes what comes back.
func (b *bridge) forward(ctx context.Context, msg []byte) {
	var head struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	json.Unmarshal(msg, &head)
	isRequest := len(head.ID) > 0 && head.Method != ""

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(msg))
	if err != nil {
		b.fail(head.ID, isRequest, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := b.hc.Do(req)
	if err != nil {
		b.fail(head.ID, isRequest, fmt.Sprintf("could not reach jitd at %s (is this machine on the tailnet?): %v", b.endpoint, err))
		return
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusAccepted:
		// A notification or a response: nothing comes back.
	case resp.StatusCode/100 != 2:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		b.fail(head.ID, isRequest, explain(resp.StatusCode, body, b.endpoint))
	case strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream"):
		b.pumpSSE(resp.Body)
	default:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			b.fail(head.ID, isRequest, "reading jitd's reply: "+err.Error())
			return
		}
		b.write(body)
	}
}

// pumpSSE writes each event's data (one JSON-RPC message) to stdout as it
// arrives. jitd answers with plain JSON today; this keeps the bridge
// working should a later jitd stream notifications during a tool call.
func (b *bridge) pumpSSE(body io.Reader) {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var data []string
	flush := func() {
		if len(data) > 0 {
			b.write([]byte(strings.Join(data, "\n")))
			data = nil
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
}

// write puts one message on stdout, newline-delimited as stdio MCP wants.
func (b *bridge) write(msg []byte) {
	msg = bytes.TrimSpace(msg)
	if len(msg) == 0 {
		return
	}
	// One message per line: an event's data may span lines, so compact it.
	var buf bytes.Buffer
	if err := json.Compact(&buf, msg); err != nil {
		b.log.Warn("bridge: jitd sent something that is not JSON", "bytes", len(msg))
		return
	}
	buf.WriteByte('\n')
	b.mu.Lock()
	defer b.mu.Unlock()
	b.out.Write(buf.Bytes())
}

// fail answers a request with a JSON-RPC error so the host does not hang on
// it; a failed notification is only logged.
func (b *bridge) fail(id json.RawMessage, isRequest bool, msg string) {
	b.log.Error("bridge: " + msg)
	if !isRequest {
		return
	}
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": msg}})
	b.write(out)
}

// explain turns jitd's HTTP refusal into one sentence a person can act on.
// jitd's errors are {"error":{"code","message"}}; Claude Desktop shows the
// host only the JSON-RPC error text, so this is all a user sees.
func explain(status int, body []byte, endpoint string) string {
	msg := strings.TrimSpace(string(body))
	var e struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		msg = e.Error.Message
	}
	switch status {
	case http.StatusUnauthorized:
		return "jitd could not identify this machine; it has to be a device on the tailnet that runs jitd: " + msg
	case http.StatusNotFound:
		return fmt.Sprintf("nothing answers at %s; -jit-url is jitd's base URL, such as http://jit (the bridge adds /mcp itself)", endpoint)
	}
	return fmt.Sprintf("jitd answered HTTP %d: %s", status, msg)
}

// endpointFor turns -jit-url into the /mcp URL. Every doc page prints
// http://jit/mcp, so a URL that already ends in /mcp is accepted too.
func endpointFor(jitURL string) string {
	u := strings.TrimRight(jitURL, "/")
	u = strings.TrimSuffix(u, "/mcp")
	return strings.TrimRight(u, "/") + "/mcp"
}

// runBridge implements "pamagent bridge [flags]" and the no-argument form.
func runBridge(ctx context.Context, jitURL string, log *slog.Logger) int {
	// No overall client timeout: a wait_for_access may legitimately take
	// four minutes. But a server that accepts the connection and never
	// answers must not hang the host forever.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 5 * time.Minute
	b := &bridge{endpoint: endpointFor(jitURL), hc: &http.Client{Transport: tr}, log: log, out: os.Stdout}
	log.Info("bridging stdio to jitd", "endpoint", b.endpoint, "version", version)
	if err := b.run(ctx, os.Stdin); err != nil && ctx.Err() == nil {
		log.Error("bridge: reading stdin", "err", err)
		return 1
	}
	return 0
}
