package jit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAttrKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"db_ro", "custom:jit_db_ro"},
		{" DB_RO ", "custom:jit_db_ro"},
		{"custom:jit_ssh", "custom:jit_ssh"},
	} {
		if got := AttrKey(tc.in); got != tc.want {
			t.Errorf("AttrKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := PostureFor("custom:jit_db_ro"); got != "posture:jit_db_ro" {
		t.Errorf("PostureFor = %q", got)
	}
}

func TestDurationJSON(t *testing.T) {
	var v struct{ D Duration }
	if err := json.Unmarshal([]byte(`{"D":"1h30m"}`), &v); err != nil || v.D != Duration(90*time.Minute) {
		t.Fatalf("string: %v %v", v.D, err)
	}
	if err := json.Unmarshal([]byte(`{"D":60000000000}`), &v); err != nil || v.D != Duration(time.Minute) {
		t.Fatalf("number: %v %v", v.D, err)
	}
	if err := json.Unmarshal([]byte(`{"D":"soon"}`), &v); err == nil {
		t.Fatal("expected error for bad duration")
	}
	for in, want := range map[string]time.Duration{
		"3d": 72 * time.Hour, "1d12h": 36 * time.Hour, "2d30m": 48*time.Hour + 30*time.Minute, "90m": 90 * time.Minute, " 2h ": 2 * time.Hour,
	} {
		if err := json.Unmarshal([]byte(`{"D":"`+in+`"}`), &v); err != nil || time.Duration(v.D) != want {
			t.Errorf("%q: got %v %v, want %v", in, time.Duration(v.D), err, want)
		}
	}
	for _, bad := range []string{"xd", "1d2x", "-1d", "d", "1d-23h", "+3d", "-5m", "3650d2562047h"} {
		if err := json.Unmarshal([]byte(`{"D":"`+bad+`"}`), &v); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
	b, _ := json.Marshal(struct{ D Duration }{Duration(30 * time.Minute)})
	if string(b) != `{"D":"30m0s"}` {
		t.Errorf("marshal = %s", b)
	}
}

func TestDurationHuman(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour: "1 hour", 90 * time.Minute: "1 hour 30 minutes", 110 * time.Minute: "1 hour 50 minutes",
		45 * time.Minute: "45 minutes", 7 * 24 * time.Hour: "7 days", 36 * time.Hour: "1 day 12 hours", 0: "-",
	} {
		if got := Duration(d).Human(); got != want {
			t.Errorf("%v: got %q, want %q", d, got, want)
		}
	}
}

func TestWorkflowValidate(t *testing.T) {
	good := func() Workflow {
		return Workflow{Name: "RDP", Attribute: "rdp", Resources: []Resource{{Name: "svc:windows-rdp"}}, Requesters: []Principal{"autogroup:member"}, Approvers: []Principal{"a@example.com"}}
	}
	w := good()
	w.Resources = []Resource{{Name: " svc:windows-rdp ", Description: " RDP "}, {Name: "svc:windows-rdp"}, {Name: ""}}
	w.Normalize()
	if err := w.Validate(); err != nil {
		t.Fatalf("good workflow: %v", err)
	}
	if len(w.Resources) != 1 || w.Resources[0].Description != "RDP" || w.Attribute != "custom:jit_rdp" || w.MaxDuration != DefaultMaxDuration {
		t.Errorf("normalize: %+v", w)
	}
	w = good()
	w.Resources = nil
	w.Normalize()
	if err := w.Validate(); err != nil {
		t.Errorf("resources are optional: %v", err)
	}
	for name, mut := range map[string]func(*Workflow){
		"no name":          func(w *Workflow) { w.Name = "" },
		"no attribute":     func(w *Workflow) { w.Attribute = "" },
		"bad attribute":    func(w *Workflow) { w.Attribute = "read-only" },
		"long attribute":   func(w *Workflow) { w.Attribute = strings.Repeat("a", 33) },
		"resource spaces":  func(w *Workflow) { w.Resources = []Resource{{Name: "svc:a b"}} },
		"long description": func(w *Workflow) { w.Resources = []Resource{{Name: "svc:a", Description: strings.Repeat("x", 201)}} },
		"no approvers":     func(w *Workflow) { w.Approvers = nil },
		"bad principal":    func(w *Workflow) { w.Requesters = []Principal{"alice"} },
		"short max":        func(w *Workflow) { w.MaxDuration = Duration(time.Second) },
		"max over a year":  func(w *Workflow) { w.MaxDuration = Duration(100000 * time.Hour) },
		"default over max": func(w *Workflow) { w.MaxDuration, w.DefaultDuration = Duration(time.Hour), Duration(2*time.Hour) },
	} {
		w := good()
		mut(&w)
		w.Normalize()
		if err := w.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
