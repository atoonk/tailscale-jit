package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailscale.com/client/local"
)

// TestMain waits out safesocket's startup grace period, during which dial
// failures are retried until the context expires instead of failing fast
// (2s, extended to 5s when any tailscaled process is running).
func TestMain(m *testing.M) {
	time.Sleep(5100 * time.Millisecond)
	os.Exit(m.Run())
}

// fakeDaemon serves a minimal LocalAPI on a unix socket so tests exercise the
// real local.Client (HTTP status handling, JSON decoding) without tailscaled.
type fakeDaemon struct {
	version        string
	state          string
	servicesStatus int
	servicesBody   string
	statusStatus   int
}

func (f fakeDaemon) start(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ts.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		if f.statusStatus != 0 {
			http.Error(w, `{"error":"denied by test"}`, f.statusStatus)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"Version":        f.version,
			"BackendState":   f.state,
			"Self":           map[string]any{"HostName": "testhost", "DNSName": "testhost.example.ts.net."},
			"CurrentTailnet": map[string]any{"Name": "example.com"},
		})
	})
	mux.HandleFunc("/localapi/v0/services", func(w http.ResponseWriter, r *http.Request) {
		if f.servicesStatus != 0 && f.servicesStatus != 200 {
			http.Error(w, f.servicesBody, f.servicesStatus)
			return
		}
		io.WriteString(w, f.servicesBody)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// callTool runs list_services through a real MCP client/server session.
func callTool(t *testing.T, socket string) (*mcp.ListToolsResult, *mcp.CallToolResult) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := mcp.NewServer(&mcp.Implementation{Name: "pamagent", Version: "test"}, nil)
	registerTools(server, &discoverer{src: &local.Client{Socket: socket}, timeout: 2 * time.Second, log: log})

	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_services"})
	if err != nil {
		t.Fatal(err)
	}
	return tools, res
}

func text(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

const populated = `{
 "svc:web": {"Name":"svc:web","Addrs":["fd7a:115c:a1e0::1","100.100.1.2"],"Ports":["tcp:443","tcp:80"]},
 "svc:db": {"Name":"svc:db","DisplayName":"Prod DB","Addrs":["100.100.1.1"],"Ports":["tcp:5432","tcp:22"],
   "Actions":[
     {"Type":"ssh","Port":22},
     {"Type":"postgresql","Port":5432,"DisplayName":"psql","Attributes":{"tailscale.com/cap/resource-name":"orders","tailscale.com/cap/skip-username":true,"tailscale.com/cap/web-client-url":"https://example.com/?a=1&b=2"}},
     {"Type":"example.com/custom","Port":5432}
   ]}
}`

func TestListServicesPopulated(t *testing.T) {
	sock := fakeDaemon{version: "1.102.2-tabc", state: "Running", servicesBody: populated}.start(t)
	tools, res := callTool(t, sock)

	if len(tools.Tools) != 1 || tools.Tools[0].Name != "list_services" {
		t.Fatalf("tools = %+v", tools.Tools)
	}
	if a := tools.Tools[0].Annotations; a == nil || !a.ReadOnlyHint {
		t.Errorf("list_services should be annotated read-only")
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", text(res))
	}

	var out listServicesOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ServiceCount != 2 || out.Services[0].Name != "svc:db" || out.Services[1].Name != "svc:web" {
		t.Fatalf("services not sorted by name: %+v", out.Services)
	}
	db, web := out.Services[0], out.Services[1]
	if db.DisplayName != "Prod DB" || web.DisplayName != "" {
		t.Errorf("display names: %q %q", db.DisplayName, web.DisplayName)
	}
	if got := strings.Join(web.Addresses, ","); got != "100.100.1.2,fd7a:115c:a1e0::1" {
		t.Errorf("addresses = %s", got)
	}
	if got := db.Ports[0].Protocol + ":" + db.Ports[0].Ports; got != "tcp:22" {
		t.Errorf("first port = %s", got)
	}
	if len(db.Actions) != 3 || db.Actions[0].Type != "ssh" || db.Actions[1].Type != "example.com/custom" || db.Actions[2].Type != "postgresql" {
		t.Fatalf("actions not sorted by port then type: %+v", db.Actions)
	}
	if db.Actions[1].KnownType || !db.Actions[2].KnownType {
		t.Errorf("known_type wrong: %+v", db.Actions)
	}
	if db.Actions[2].Attributes["tailscale.com/cap/resource-name"] != "orders" || db.Actions[2].Attributes["tailscale.com/cap/skip-username"] != true {
		t.Errorf("attributes = %+v", db.Actions[2].Attributes)
	}
	if !strings.Contains(text(res), "https://example.com/?a=1&b=2") {
		t.Errorf("URL in summary should not be HTML-escaped: %s", text(res))
	}
	if !strings.Contains(text(res), "2 Tailscale Service(s) visible to testhost.example.ts.net") {
		t.Errorf("summary = %s", text(res))
	}

	// Determinism: identical output on repeated calls despite map iteration order.
	for range 5 {
		_, again := callTool(t, sock)
		if text(again) != text(res) {
			t.Fatal("output not deterministic")
		}
	}
}

func TestListServicesErrors(t *testing.T) {
	tests := []struct {
		name string
		sock func(t *testing.T) string
		want string
	}{
		{"empty", fakeDaemon{version: "1.102.2", state: "Running", servicesBody: "{}"}.start, "No Tailscale Services are visible"},
		{"null body", fakeDaemon{version: "1.102.2", state: "Running", servicesBody: "null"}.start, "No Tailscale Services are visible"},
		{"daemon unavailable", func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.sock") }, "daemon_unavailable"},
		{"access denied (403)", fakeDaemon{statusStatus: 403}.start, "permission_denied"},
		{"old version", fakeDaemon{version: "1.96.4-tfoo", state: "Running"}.start, "unsupported_daemon_version: tailscaled 1.96.4-tfoo"},
		{"unknown endpoint (404)", fakeDaemon{version: "weird", state: "Running", servicesStatus: 404, servicesBody: "404 page not found"}.start, "unsupported_daemon_version"},
		{"no netmap (503)", fakeDaemon{version: "1.102.2", state: "Running", servicesStatus: 503, servicesBody: "no netmap"}.start, "not_ready"},
		{"logged out", fakeDaemon{version: "1.102.2", state: "NeedsLogin"}.start, `tailscale_not_running: tailscaled is reachable but its state is "NeedsLogin"`},
		{"socket permission", func(t *testing.T) string {
			if os.Geteuid() == 0 {
				t.Skip("root bypasses socket permissions")
			}
			sock := fakeDaemon{version: "1.102.2", state: "Running", servicesBody: "{}"}.start(t)
			os.Chmod(sock, 0)
			return sock
		}, "permission_denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, res := callTool(t, tt.sock(t))
			if !strings.Contains(text(res), tt.want) {
				t.Fatalf("got %q, want substring %q", text(res), tt.want)
			}
			if wantErr := !strings.HasPrefix(tt.want, "No "); res.IsError != wantErr {
				t.Errorf("IsError = %v, want %v", res.IsError, wantErr)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "slow.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))

	d := &discoverer{src: &local.Client{Socket: sock}, timeout: 100 * time.Millisecond, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err = d.discover(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "timeout:") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstructions(t *testing.T) {
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "pamagent", Version: "test"}, &mcp.ServerOptions{Instructions: instructions("http://jit.example", "/x/pamagent wait -jit-url http://jit.example")})
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	got := cs.InitializeResult().Instructions
	for _, want := range []string{"submitted an access request", `"url" field`, "http://jit.example/requests/req_", "list_services", "list_requestable", "/x/pamagent wait -jit-url http://jit.example <request_id>", "WITHOUT a username or password", "Never hunt for, guess or brute-force real credentials", "MongoDB, MS SQL", "tailscale service list"} {
		if !strings.Contains(got, want) {
			t.Errorf("instructions missing %q:\n%s", want, got)
		}
	}
}
