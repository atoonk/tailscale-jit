package jit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustUpdate(t *testing.T, s *Store, fn func(d *Data) error) {
	t.Helper()
	if err := s.Update(fn); err != nil {
		t.Fatal(err)
	}
}

func queryString(t *testing.T, s *Store, q string) string {
	t.Helper()
	var v string
	if err := s.db.QueryRow(q).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jit.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mustUpdate(t, s, func(d *Data) error {
		d.Workflows["wf_1"] = &Workflow{ID: "wf_1", Name: "one", MaxDuration: DefaultMaxDuration}
		d.Requests["req_1"] = &AccessRequest{ID: "req_1", WorkflowID: "wf_1", Status: StatusPending}
		return nil
	})
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, %v; want 0600", filepath.Base(p), fi.Mode(), err)
		}
	}
	if typ := queryString(t, s, `SELECT typeof(data) FROM requests`); typ != "text" {
		t.Errorf("data is stored as %s, want text", typ)
	}
	s.Close()

	s2 := openStore(t, path)
	s2.View(func(d *Data) {
		if d.Workflows["wf_1"].Name != "one" || d.Requests["req_1"].Status != StatusPending {
			t.Errorf("reloaded data = %+v", d)
		}
	})
	if s2.Mode != 0o600 {
		t.Errorf("Mode = %v", s2.Mode)
	}
}

func TestStoreWritesOnlyChangedRows(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "jit.db"))
	mustUpdate(t, s, func(d *Data) error {
		d.Workflows["wf_1"] = &Workflow{ID: "wf_1", Name: "one"}
		d.Workflows["wf_2"] = &Workflow{ID: "wf_2", Name: "two"}
		d.Requests["req_1"] = &AccessRequest{ID: "req_1", WorkflowID: "wf_1", Status: StatusPending}
		d.Requests["req_2"] = &AccessRequest{ID: "req_2", WorkflowID: "wf_1", Status: StatusPending}
		return nil
	})
	if s.Changes() != 1 {
		t.Errorf("changes = %d, want 1", s.Changes())
	}

	// Change one request, delete the other and delete a flow.
	s.mu.Lock()
	s.d.Requests["req_1"].Status = StatusApproved
	delete(s.d.Requests, "req_2")
	delete(s.d.Workflows, "wf_2")
	rows, _ := s.diff()
	s.mu.Unlock()
	var got []string
	for _, r := range rows {
		what := " written"
		if r.data == nil {
			what = " deleted"
		}
		got = append(got, r.key.id+what)
	}
	slices.Sort(got)
	if want := []string{"req_1 written", "req_2 deleted", "wf_2 deleted"}; !slices.Equal(got, want) {
		t.Errorf("diff = %v, want %v", got, want)
	}
	mustUpdate(t, s, func(d *Data) error { return nil })
	if st := queryString(t, s, `SELECT status FROM requests WHERE id = 'req_1'`); st != string(StatusApproved) {
		t.Errorf("req_1 status in the database: %q", st)
	}
	if n := queryString(t, s, `SELECT (SELECT count(*) FROM requests) || ' ' || (SELECT count(*) FROM workflows)`); n != "1 1" {
		t.Errorf("requests and flows left: %s, want 1 1", n)
	}

	// Nothing changed: nothing written, and no change for pages to see.
	before := s.Changes()
	mustUpdate(t, s, func(d *Data) error { d.Requests["req_1"].Status = StatusApproved; return nil })
	mustUpdate(t, s, func(d *Data) error { return errNoChange })
	if s.Changes() != before {
		t.Error("a no-op update counted as a change")
	}
}

func TestStoreUpdateQuiet(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "jit.db"))
	mustUpdate(t, s, func(d *Data) error {
		d.Requests["req_1"] = &AccessRequest{ID: "req_1", WorkflowID: "wf_1", Status: StatusApproved}
		return nil
	})
	before := s.Changes()
	err := s.UpdateQuiet(func(d *Data) (bool, error) {
		d.Requests["req_1"].LastError = "bookkeeping"
		return false, nil
	})
	if err != nil || s.Changes() != before {
		t.Errorf("quiet update: err %v, changes %d -> %d", err, before, s.Changes())
	}
	if !strings.Contains(queryString(t, s, `SELECT data FROM requests`), "bookkeeping") {
		t.Error("quiet update was not saved")
	}
	err = s.UpdateQuiet(func(d *Data) (bool, error) {
		d.Requests["req_1"].Status = StatusRevoked
		return true, nil
	})
	if err != nil || s.Changes() != before+1 {
		t.Errorf("a visible quiet update: err %v, changes %d -> %d", err, before, s.Changes())
	}
}

func TestStoreUpdateErrorRollsBack(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "jit.db"))
	mustUpdate(t, s, func(d *Data) error {
		d.Workflows["wf_1"] = &Workflow{ID: "wf_1", Name: "one"}
		return nil
	})
	unchanged := func(when string) {
		t.Helper()
		s.View(func(d *Data) {
			if len(d.Workflows) != 1 || d.Workflows["wf_1"].Name != "one" || len(d.Requests) != 0 {
				t.Errorf("%s: the update was kept: %+v %+v", when, d.Workflows, d.Requests)
			}
		})
	}
	change := func(d *Data) {
		d.Workflows["wf_1"].Name = "changed"
		d.Workflows["wf_2"] = &Workflow{ID: "wf_2"}
	}

	boom := errors.New("boom")
	if err := s.Update(func(d *Data) error { change(d); return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	unchanged("after an error")

	func() {
		defer func() { recover() }()
		s.Update(func(d *Data) error { change(d); panic("boom") })
	}()
	unchanged("after a panic")

	if err := s.Update(func(d *Data) error { d.Requests["req_x"] = nil; return nil }); err == nil {
		t.Error("a nil request was accepted")
	}
	unchanged("after a nil request")

	// The write itself fails.
	s.db.Close()
	before := s.Changes()
	if err := s.Update(func(d *Data) error { change(d); return nil }); err == nil {
		t.Fatal("expected an error from a closed database")
	}
	unchanged("after a failed write")
	if s.Changes() != before {
		t.Error("a failed write counted as a change")
	}
}

const oldJSON = `{"version":1,
	"workflows":{"wf_1":{"id":"wf_1","name":"Database (read-only)","attribute":"custom:jit_db_ro"}},
	"requests":{"req_1":{"id":"req_1","workflow_id":"wf_1","status":"expired",
		"requester":{"login":"maya@example.com","device_id":"n1"},"created_at":"2026-10-01T12:00:00Z"}}}`

func TestStoreImportsJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "data.json")
	writeFile(t, jsonPath, oldJSON)

	s, err := Open(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != filepath.Join(dir, "data.db") || s.Imported != jsonPath {
		t.Errorf("path %q, imported %q", s.Path, s.Imported)
	}
	if s.Changes() != 0 {
		t.Errorf("an import counted as %d changes", s.Changes())
	}
	if got := queryString(t, s, `SELECT requester || ' ' || created_at FROM requests WHERE id = 'req_1'`); got != "maya@example.com 2026-10-01T12:00:00.000000000Z" {
		t.Errorf("request row: %q", got)
	}
	s.Close()
	if fi, err := os.Stat(filepath.Join(dir, "data.db")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("imported database: %v, %v", fi.Mode(), err)
	}
	if exists(filepath.Join(dir, "data.db.importing")) {
		t.Error("the temporary import database was left behind")
	}

	// The JSON file is left alone, and the next start uses the database.
	if b, _ := os.ReadFile(jsonPath); !bytes.Equal(b, []byte(oldJSON)) {
		t.Error("the JSON file was changed")
	}
	writeFile(t, jsonPath, `{"workflows":{}}`)
	s = openStore(t, jsonPath)
	if s.Imported != "" || s.Ignored != jsonPath {
		t.Errorf("imported %q, ignored %q", s.Imported, s.Ignored)
	}
	s.View(func(d *Data) {
		if d.Workflows["wf_1"].Attribute != "custom:jit_db_ro" || d.Requests["req_1"].Status != StatusExpired {
			t.Errorf("after reopening: %+v", d)
		}
	})
}

func TestStoreUpgradeWithDefaultName(t *testing.T) {
	// The old default -data was jit-data.json; the new one is jit.db. An
	// upgrade that keeps the default must not start empty.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, LegacyDataFile), oldJSON)
	s := openStore(t, filepath.Join(dir, "jit.db"))
	if s.Imported != filepath.Join(dir, LegacyDataFile) {
		t.Errorf("imported %q", s.Imported)
	}
	s.View(func(d *Data) {
		if len(d.Workflows) != 1 || len(d.Requests) != 1 {
			t.Errorf("imported %d flows and %d requests", len(d.Workflows), len(d.Requests))
		}
	})

	// Any other name starts empty.
	other := openStore(t, filepath.Join(dir, "other.db"))
	if other.Imported != "" {
		t.Error("other.db imported jit-data.json")
	}
}

func TestStoreInterruptedImport(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "data.json")
	writeFile(t, jsonPath, oldJSON)
	// What a crash during the import leaves: only the temporary database.
	writeFile(t, filepath.Join(dir, "data.db.importing"), "")
	writeFile(t, filepath.Join(dir, "data.db.importing-wal"), "partial")

	s := openStore(t, jsonPath)
	if s.Imported != jsonPath {
		t.Fatal("did not import after an interrupted import")
	}
	s.View(func(d *Data) {
		if len(d.Workflows) != 1 {
			t.Errorf("imported %d flows", len(d.Workflows))
		}
	})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "importing") {
			t.Errorf("left behind: %s", e.Name())
		}
	}
}

func TestStoreBadImports(t *testing.T) {
	for name, content := range map[string]string{
		"corrupt":      "{not json",
		"null request": `{"requests":{"req_1":null}}`,
		"id mismatch":  `{"workflows":{"wf_1":{"id":"wf_2"}}}`,
		"empty id":     `{"requests":{"":{"id":""}}}`,
		"newer":        `{"version":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "jit.json")
			writeFile(t, path, content)
			if _, err := Open(path); err == nil {
				t.Fatal("expected an error")
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Errorf("a failed import left files behind: %v", entries)
			}
		})
	}

	// A .json that isn't there is a mistake, not a new install.
	dir := t.TempDir()
	if _, err := Open(filepath.Join(dir, "typo.json")); err == nil || !strings.Contains(err.Error(), "nothing to import") {
		t.Errorf("err = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
}

func TestStoreRefusesOtherFiles(t *testing.T) {
	dir := t.TempDir()

	notDB := filepath.Join(dir, "text.db")
	writeFile(t, notDB, "this is not a database, just some text that is long enough")
	if _, err := Open(notDB); err == nil {
		t.Error("opened a text file")
	}

	// Someone else's SQLite database: refuse rather than add tables to it.
	foreign := filepath.Join(dir, "foreign.db")
	s := openStore(t, foreign)
	for _, q := range []string{`PRAGMA user_version = 0`, `CREATE TABLE notes (x TEXT)`, `DROP TABLE workflows`, `DROP TABLE requests`} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	s.Close()
	if _, err := Open(foreign); err == nil || !strings.Contains(err.Error(), "not a jitd database") {
		t.Errorf("foreign database: err = %v", err)
	}

	// A database from a newer jitd.
	newer := filepath.Join(dir, "newer.db")
	s = openStore(t, newer)
	if _, err := s.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(newer); err == nil || !strings.Contains(err.Error(), "newer jitd") {
		t.Errorf("newer database: err = %v", err)
	}
}

func TestStoreMigratesV1(t *testing.T) {
	// A schema 1 database as the first SQLite jitd wrote it: data as a blob,
	// created_at with trimmed fractions.
	path := filepath.Join(t.TempDir(), "jit.db")
	s := openStore(t, path)
	for _, q := range []string{
		`DROP TABLE workflows`, `DROP TABLE requests`, schemaV1, `PRAGMA user_version = 1`,
		`INSERT INTO workflows VALUES ('wf_1', 'one', CAST('{"id":"wf_1","name":"one"}' AS BLOB))`,
		`INSERT INTO requests VALUES ('req_1', 'wf_1', 'maya', 'expired', '2026-10-01T12:00:00.5Z',
			CAST('{"id":"req_1","workflow_id":"wf_1","status":"expired","created_at":"2026-10-01T12:00:00.5Z"}' AS BLOB))`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	s.Close()

	s = openStore(t, path)
	if got := queryString(t, s, `SELECT typeof(data) || ' ' || created_at FROM requests`); got != "text 2026-10-01T12:00:00.500000000Z" {
		t.Errorf("migrated request row: %q", got)
	}
	if got := queryString(t, s, `SELECT typeof(data) FROM workflows`); got != "text" {
		t.Errorf("migrated flow row: %q", got)
	}
	if v, _ := s.version(); v != schemaVersion {
		t.Errorf("version %d", v)
	}
	s.View(func(d *Data) {
		if d.Workflows["wf_1"].Name != "one" || d.Requests["req_1"].Status != StatusExpired {
			t.Errorf("after the migration: %+v", d)
		}
	})
}

func TestStoreReadOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenReadOnly(filepath.Join(dir, "jit.db")); err == nil {
		t.Error("opened a database that does not exist")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("created %v", entries)
	}
	s := openStore(t, filepath.Join(dir, "jit.db"))
	mustUpdate(t, s, func(d *Data) error {
		d.Workflows["wf_1"] = &Workflow{ID: "wf_1", Name: "one"}
		return nil
	})
	s.Close()
	ro, err := OpenReadOnly(filepath.Join(dir, "jit.json")) // a .json name finds its .db
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := ro.Update(func(d *Data) error { d.Workflows["wf_1"].Name = "x"; return nil }); err == nil {
		t.Error("wrote to a read-only database")
	}
}

func TestStoreOddPaths(t *testing.T) {
	// '?', '#' and '%' are URI syntax; the path must still mean that file.
	dir := t.TempDir()
	for _, name := range []string{"a?mode=memory.db", "b#2.db", "c%41.db"} {
		path := filepath.Join(dir, name)
		s := openStore(t, path)
		mustUpdate(t, s, func(d *Data) error {
			d.Workflows["wf_1"] = &Workflow{ID: "wf_1", Name: name}
			return nil
		})
		s.Close()
		if !exists(path) {
			t.Errorf("%s: no such file", name)
			continue
		}
		s = openStore(t, path)
		s.View(func(d *Data) {
			if len(d.Workflows) != 1 {
				t.Errorf("%s: not saved in that file", name)
			}
		})
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == "a" || e.Name() == "b" || e.Name() == "cA.db" {
			t.Errorf("opened %s instead", e.Name())
		}
	}
}

func TestTimeColumnSorts(t *testing.T) {
	a := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	b := a.Add(500 * time.Millisecond)
	if !(timeColumn(a) < timeColumn(b)) {
		t.Errorf("%s does not sort before %s", timeColumn(a), timeColumn(b))
	}
}
