package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"tailscale.com/tsnet"

	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

type fakeKeys struct {
	createErr error
	created   []string // tags of each key
	ttl       time.Duration
	deleted   []string
}

func (f *fakeKeys) CreateAuthKey(_ context.Context, tags []string, ttl time.Duration, _ string) (tsapi.AuthKey, error) {
	if f.createErr != nil {
		return tsapi.AuthKey{}, f.createErr
	}
	f.created = append(f.created, tags...)
	f.ttl = ttl
	return tsapi.AuthKey{ID: "kABC", Key: "tskey-auth-kABC-secret"}, nil
}

func (f *fakeKeys) DeleteAuthKey(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

func TestFederatedNodeKey(t *testing.T) {
	federated := map[string]string{"TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "jwt"}
	cases := []struct {
		name string
		vars map[string]string
		want bool
	}{
		{name: "nothing set", vars: map[string]string{}},
		{name: "federated identity", vars: federated, want: true},
		{name: "auth key wins", vars: map[string]string{"TS_AUTHKEY": "tskey-auth-x", "TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "jwt"}},
		{name: "oauth client wins", vars: map[string]string{"TS_OAUTH_CLIENT_ID": "cid", "TS_OAUTH_CLIENT_SECRET": "s", "TS_ID_TOKEN": "jwt"}},
		{name: "api key", vars: map[string]string{"TS_API_KEY": "tskey-api-x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeKeys{}
			srv := &tsnet.Server{}
			cleanup, err := federatedNodeKey(context.Background(), srv, "tag:jit", tc.vars, func(map[string]string) (authKeys, error) { return f, nil })
			if err != nil {
				t.Fatal(err)
			}
			if (cleanup != nil) != tc.want {
				t.Fatalf("cleanup set = %v, want %v", cleanup != nil, tc.want)
			}
			if !tc.want {
				if srv.AuthKey != "" || srv.AdvertiseTags != nil || len(f.created) != 0 {
					t.Fatalf("did something: server %+v, keys %+v", srv, f)
				}
				return
			}
			if srv.AuthKey != "tskey-auth-kABC-secret" || !slices.Equal(srv.AdvertiseTags, []string{"tag:jit"}) {
				t.Errorf("server = %+v", srv)
			}
			if !slices.Equal(f.created, []string{"tag:jit"}) || f.ttl != nodeKeyTTL {
				t.Errorf("created %v with ttl %v", f.created, f.ttl)
			}
			if err := cleanup(context.Background()); err != nil || !slices.Equal(f.deleted, []string{"kABC"}) {
				t.Errorf("cleanup: %v, deleted %v", err, f.deleted)
			}
		})
	}
}

func TestFederatedNodeKeyCreateFails(t *testing.T) {
	f := &fakeKeys{createErr: errors.New("403 missing scope")}
	srv := &tsnet.Server{}
	cleanup, err := federatedNodeKey(context.Background(), srv, "tag:jit", map[string]string{"TS_OAUTH_CLIENT_ID": "cid", "TS_ID_TOKEN": "jwt"}, func(map[string]string) (authKeys, error) { return f, nil })
	if err == nil || cleanup != nil || srv.AuthKey != "" || srv.AdvertiseTags != nil {
		t.Fatalf("err %v, cleanup %v, server %+v", err, cleanup != nil, srv)
	}
}

func TestNodeKeyVars(t *testing.T) {
	file := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(file, []byte("TS_OAUTH_CLIENT_ID=from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TS_OAUTH_CLIENT_ID", "from-env")
	t.Setenv("TS_ID_TOKEN", "file:/token")
	t.Setenv("TS_AUTHKEY", "")
	vars, err := nodeKeyVars(file)
	if err != nil {
		t.Fatal(err)
	}
	if vars["TS_OAUTH_CLIENT_ID"] != "from-file" || vars["TS_ID_TOKEN"] != "file:/token" {
		t.Fatalf("vars = %v", vars)
	}
	if _, err := nodeKeyVars(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("missing env file: %v", err)
	}
}
