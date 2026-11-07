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
)

// bridge is "pamagent bridge": an MCP server on stdin/stdout that forwards
// every message to jitd's MCP endpoint over the tailnet, for hosts that only
// run local (stdio) servers. jitd's /mcp is stateless, so each message is one
// HTTP POST, answered with JSON or a short event stream; the replies, and
// any notifications jitd sends while a tool runs, go back out on stdout.
// Nothing is interpreted here: the host and jitd negotiate everything,
// including the MCP Apps view, between themselves.
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
	defer wg.Wait()
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
		b.fail(head.ID, isRequest, fmt.Sprintf("jitd answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
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
// arrives, so progress notifications reach the host while a tool runs.
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

// runBridge implements "pamagent bridge [flags]" and the no-argument form.
func runBridge(ctx context.Context, jitURL string, log *slog.Logger) int {
	b := &bridge{endpoint: strings.TrimSuffix(jitURL, "/") + "/mcp", hc: &http.Client{}, log: log, out: os.Stdout}
	log.Info("bridging stdio to jitd", "endpoint", b.endpoint, "version", version)
	if err := b.run(ctx, os.Stdin); err != nil && ctx.Err() == nil {
		log.Error("bridge: reading stdin", "err", err)
		return 1
	}
	return 0
}
