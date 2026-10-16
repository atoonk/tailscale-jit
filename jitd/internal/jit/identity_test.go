package jit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"tailscale.com/client/local"
)

// fakeWhoIs serves /localapi/v0/whois on a unix socket, like tailscaled.
func fakeWhoIs(t *testing.T, peers map[string]string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ts.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/whois", func(w http.ResponseWriter, r *http.Request) {
		body, ok := peers[r.URL.Query().Get("addr")]
		if !ok {
			http.Error(w, "no match for IP:port", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestWhoIsResolver(t *testing.T) {
	sock := fakeWhoIs(t, map[string]string{
		"100.64.0.7:5555": `{"Node":{"StableID":"nMAC123CNTRL","Name":"mac.example.ts.net.","ComputedName":"mac"},
			"UserProfile":{"LoginName":"alice@example.com","DisplayName":"Alice"}}`,
		"100.64.0.9:4444": `{"Node":{"StableID":"nCI","Name":"ci.example.ts.net.","Tags":["tag:agent"]},
			"UserProfile":{"LoginName":"tagged-devices","DisplayName":"Tagged Devices"}}`,
	})
	res := &WhoIsResolver{Client: &local.Client{Socket: sock}}
	resolve := func(addr string) (Identity, error) {
		r := httptest.NewRequest("GET", "/v1/me", nil)
		r.RemoteAddr = addr
		return res.Resolve(context.Background(), r)
	}

	id, err := resolve("100.64.0.7:5555")
	if err != nil {
		t.Fatal(err)
	}
	if id.Login != "alice@example.com" || id.DeviceID != "nMAC123CNTRL" || id.DeviceName != "mac" || id.Tagged() {
		t.Errorf("member identity = %+v", id)
	}

	id, err = resolve("100.64.0.9:4444")
	if err != nil {
		t.Fatal(err)
	}
	if !id.Tagged() || !slices.Equal(id.Tags, []string{"tag:agent"}) || id.DeviceName != "ci.example.ts.net" {
		t.Errorf("tagged identity = %+v", id)
	}

	if _, err := resolve("100.64.0.1:1"); code(err) != "identity_unavailable" {
		t.Errorf("unknown peer: %v", err)
	}
}

func TestIdentityJSON(t *testing.T) {
	b, _ := json.Marshal(Identity{Login: "a@b.c", DeviceID: "n1"})
	if string(b) != `{"login":"a@b.c","device_id":"n1"}` {
		t.Errorf("json = %s", b)
	}
}
