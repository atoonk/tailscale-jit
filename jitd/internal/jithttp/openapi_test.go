package jithttp

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// apiSource is api.go, read from disk so the test tracks the registered
// routes. The one templated route, /v1/requests/{id}/{action}, is expanded.
func apiSource(t *testing.T) string {
	b, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	var expanded []string
	for _, a := range []string{"approve", "decline", "cancel", "revoke"} {
		expanded = append(expanded, `mux.HandleFunc("POST /v1/requests/{id}/`+a+`"`)
	}
	return strings.Replace(src, `mux.HandleFunc("POST /v1/requests/{id}/{action}"`, strings.Join(expanded, "\n"), 1)
}

// Every /v1 route the server registers must be documented, and the spec must
// be valid JSON with those paths.
func TestOpenAPICoversRoutes(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	s := &Server{}
	if err := json.Unmarshal([]byte(s.openAPI()), &spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	src := apiSource(t)
	re := regexp.MustCompile(`mux\.HandleFunc\("(GET|POST|PUT|DELETE) (/v1/[^"]*)"`)
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		method, path := strings.ToLower(m[1]), m[2]
		ops, ok := spec.Paths[path]
		if !ok {
			t.Errorf("route %s %s is not in openapi.json", m[1], path)
			continue
		}
		if _, ok := ops[method]; !ok {
			t.Errorf("route %s %s: method missing in openapi.json", m[1], path)
		}
	}
	for path := range spec.Paths {
		if !strings.Contains(src, `"GET `+path+`"`) && !strings.Contains(src, `"POST `+path+`"`) && !strings.Contains(src, `"PUT `+path+`"`) && !strings.Contains(src, `"DELETE `+path+`"`) {
			t.Errorf("openapi.json documents %s, which the server does not serve", path)
		}
	}
}
