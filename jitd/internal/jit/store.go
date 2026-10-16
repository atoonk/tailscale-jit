package jit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure Go, so jitd still builds with CGO_ENABLED=0
)

// Data is everything jitd persists.
type Data struct {
	// Version is the format of the JSON data file older jitd versions kept
	// (see Open). The database has its own version (schemaVersion).
	Version   int                       `json:"version"`
	Workflows map[string]*Workflow      `json:"workflows"`
	Requests  map[string]*AccessRequest `json:"requests"`
}

// LegacyDataFile is the data file of jitd versions before SQLite. A new
// database called jit.db is filled from it when it sits next to it.
const LegacyDataFile = "jit-data.json"

// schemaVersion is kept in PRAGMA user_version. To change the tables, add a
// step to migrate and bump it; never edit schemaV1 or an existing step.
const schemaVersion = 2

const schemaV1 = `
CREATE TABLE workflows (
	id   TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	data TEXT NOT NULL -- the Workflow as JSON
);
CREATE TABLE requests (
	id          TEXT PRIMARY KEY,
	workflow_id TEXT NOT NULL,
	requester   TEXT NOT NULL,
	status      TEXT NOT NULL,
	created_at  TEXT NOT NULL,
	data        TEXT NOT NULL -- the AccessRequest as JSON
);
-- jitd reads everything at start; these are for people with the sqlite3 command line.
CREATE INDEX requests_status ON requests(status);
CREATE INDEX requests_workflow ON requests(workflow_id);
CREATE INDEX requests_created ON requests(created_at);
`

// timeColumn formats created_at with a fixed width, so the column sorts in
// time order as text (RFC 3339 with trimmed fractions does not).
func timeColumn(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// errNoChange, returned by an Update function that changed nothing, skips
// comparing every row with the database. Update then returns nil.
var errNoChange = errors.New("no change")

// Store keeps approval flows and access requests in a SQLite database, with a
// working copy in memory. Each row holds the object as JSON, plus a few
// columns for ad-hoc queries. An Update writes only the rows that changed,
// in one transaction.
//
// jitd must be the only writer: it does not see changes made to the database
// by anything else while it runs.
type Store struct {
	db      *sql.DB
	mu      sync.Mutex
	d       Data
	saved   map[rowKey][]byte // each row's JSON as it is in the database
	changes uint64
	broken  error // set if the working copy could not be put back after a failed update

	// Path is the database file. Imported is the JSON file it was just
	// filled from, or "". Ignored is a JSON file named in place of the
	// database that was not read because the database already existed.
	Path, Imported, Ignored string
	// Mode is the database file's permissions when it already existed (jitd
	// creates it 0600), so jitd can warn if others can read it.
	Mode fs.FileMode
}

type rowKey struct {
	table string // "workflows" or "requests"
	id    string
}

// Open opens the SQLite database at path, creating it if needed.
//
// It also upgrades from the JSON data file of older jitd versions:
//   - If path ends in ".json", the database is the same name with ".db".
//     When that does not exist yet, it is filled from the JSON file.
//   - A new database called jit.db is filled from jit-data.json next to it,
//     if there is one (the old default).
//
// The JSON file is left alone. The import is all or nothing: the database is
// built under another name and renamed into place when it is complete.
func Open(path string) (*Store, error) {
	var from string
	if filepath.Ext(path) == ".json" {
		from = path
		path = path[:len(path)-len(".json")] + ".db"
	}
	if fi, err := os.Stat(path); err == nil {
		s, err := openDB(path, false)
		if s != nil {
			s.Ignored, s.Mode = from, fi.Mode().Perm()
		}
		return s, err
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	// A new database.
	if from == "" && filepath.Base(path) == "jit.db" {
		if old := filepath.Join(filepath.Dir(path), LegacyDataFile); exists(old) {
			from = old
		}
	}
	if from == "" {
		if err := createPrivate(path); err != nil {
			return nil, err
		}
		s, err := openDB(path, false)
		if err != nil {
			removeDB(path)
		}
		return s, err
	}
	if _, err := os.Stat(from); err != nil {
		return nil, fmt.Errorf("nothing to import: %w (name a .db file to start with an empty database)", err)
	}
	tmp := path + ".importing"
	removeDB(tmp) // left over from an import that was interrupted
	if err := buildFrom(tmp, from); err != nil {
		removeDB(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		removeDB(tmp)
		return nil, err
	}
	syncDir(filepath.Dir(path))
	s, err := openDB(path, false)
	if err != nil {
		return nil, err
	}
	s.Imported = from
	return s, nil
}

// OpenReadOnly opens an existing database without changing it.
func OpenReadOnly(path string) (*Store, error) {
	if filepath.Ext(path) == ".json" {
		path = path[:len(path)-len(".json")] + ".db"
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return openDB(path, true)
}

// buildFrom creates the database tmp from the JSON data file from.
func buildFrom(tmp, from string) error {
	if err := createPrivate(tmp); err != nil {
		return err
	}
	s, err := openDB(tmp, false)
	if err != nil {
		return err
	}
	if err := s.importJSON(from); err != nil {
		s.Close()
		return err
	}
	if err := s.Close(); err != nil { // checkpoints the WAL into tmp and removes it
		return err
	}
	if exists(tmp + "-wal") {
		return errors.New("importing: the database was not completely written")
	}
	return nil
}

func openDB(path string, readOnly bool) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// A file: URI, so the path is escaped: '?', '#' and '%' in it must not
	// be read as URI syntax.
	q := "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_txlock=immediate"
	if readOnly {
		q = "mode=ro&_pragma=busy_timeout(5000)"
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String() + "?" + q
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// jitd is the only user, and Store.mu orders every access anyway.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Path: path}
	if readOnly {
		err = s.checkVersion()
	} else {
		err = s.migrate()
	}
	if err == nil {
		err = s.load()
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func (s *Store) version() (int, error) {
	var v int
	err := s.db.QueryRow("PRAGMA user_version").Scan(&v)
	return v, err
}

func (s *Store) checkVersion() error {
	v, err := s.version()
	if err == nil && v != schemaVersion {
		err = fmt.Errorf("the database is at schema %d; this jitd needs %d (start jitd once to upgrade it)", v, schemaVersion)
	}
	return err
}

// migrate brings the database to schemaVersion, in one transaction.
func (s *Store) migrate() error {
	v, err := s.version()
	if err != nil {
		return err
	}
	switch {
	case v == schemaVersion:
		return nil
	case v > schemaVersion:
		return fmt.Errorf("the database was written by a newer jitd (schema %d; this jitd knows up to %d): run the newer jitd, or restore a backup", v, schemaVersion)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if v < 1 {
		var n int
		if err := tx.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errors.New("this is not a jitd database (it has tables of its own)")
		}
		if _, err := tx.Exec(schemaV1); err != nil {
			return err
		}
	}
	if v < 2 {
		if err := migrateV2(tx); err != nil {
			return fmt.Errorf("upgrading to schema 2: %w", err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateV2 stores data as text rather than as a blob, and created_at with a
// fixed width (see timeColumn).
func migrateV2(tx *sql.Tx) error {
	if _, err := tx.Exec(`UPDATE workflows SET data = CAST(data AS TEXT)`); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id, data FROM requests`)
	if err != nil {
		return err
	}
	created := map[string]string{}
	for rows.Next() {
		var id string
		var b []byte
		if err := rows.Scan(&id, &b); err != nil {
			rows.Close()
			return err
		}
		var r AccessRequest
		if err := json.Unmarshal(b, &r); err != nil {
			rows.Close()
			return fmt.Errorf("request %s: %w", id, err)
		}
		created[id] = timeColumn(r.CreatedAt)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for id, c := range created {
		if _, err := tx.Exec(`UPDATE requests SET data = CAST(data AS TEXT), created_at = ? WHERE id = ?`, c, id); err != nil {
			return err
		}
	}
	return nil
}

// load reads every row into the working copy.
func (s *Store) load() error {
	s.saved = map[rowKey][]byte{}
	rows, err := s.db.Query("SELECT 'workflows', id, data FROM workflows UNION ALL SELECT 'requests', id, data FROM requests")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k rowKey
		var b []byte
		if err := rows.Scan(&k.table, &k.id, &b); err != nil {
			return err
		}
		s.saved[k] = b
	}
	if err := rows.Err(); err != nil {
		return err
	}
	d, err := s.decode()
	if err != nil {
		return err
	}
	s.d = d
	return nil
}

// decode builds a working copy from the stored rows.
func (s *Store) decode() (Data, error) {
	d := Data{Version: 1, Workflows: map[string]*Workflow{}, Requests: map[string]*AccessRequest{}}
	for k, b := range s.saved {
		var err error
		if k.table == "workflows" {
			w := new(Workflow)
			err = json.Unmarshal(b, w)
			d.Workflows[k.id] = w
		} else {
			r := new(AccessRequest)
			err = json.Unmarshal(b, r)
			d.Requests[k.id] = r
		}
		if err != nil {
			return d, fmt.Errorf("%s %s: %w", singular(k.table), k.id, err)
		}
	}
	return d, nil
}

func singular(table string) string {
	if table == "workflows" {
		return "flow"
	}
	return "request"
}

// importJSON fills a new, empty database from the data file of an older jitd.
func (s *Store) importJSON(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var old Data
	if err := json.Unmarshal(b, &old); err != nil {
		return fmt.Errorf("importing %s: %w", path, err)
	}
	if old.Version > 1 {
		return fmt.Errorf("importing %s: unknown version %d", path, old.Version)
	}
	for id, w := range old.Workflows {
		if w == nil || w.ID == "" || w.ID != id {
			return fmt.Errorf("importing %s: flow %q is empty or has another id", path, id)
		}
	}
	for id, r := range old.Requests {
		if r == nil || r.ID == "" || r.ID != id {
			return fmt.Errorf("importing %s: request %q is empty or has another id", path, id)
		}
	}
	err = s.Update(func(d *Data) error {
		d.Workflows, d.Requests = old.Workflows, old.Requests
		if d.Workflows == nil {
			d.Workflows = map[string]*Workflow{}
		}
		if d.Requests == nil {
			d.Requests = map[string]*AccessRequest{}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("importing %s: %w", path, err)
	}
	s.changes = 0
	return nil
}

// Close closes the database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// View runs fn with read access under the lock. fn must not keep references.
func (s *Store) View(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.d)
}

// Update runs fn under the lock and, if it returns nil, saves the rows it
// changed. If fn fails or panics, or saving fails, the working copy goes back
// to what is in the database. A no-op update (for example a verification
// that found nothing new) neither writes nor counts as a change, so pages do
// not reload for it.
func (s *Store) Update(fn func(d *Data) error) error {
	return s.update(fn, func() bool { return true })
}

// UpdateQuiet is Update for bookkeeping nobody is waiting to see (for
// example the time of the last verification): it saves but does not count
// as a change. fn returns whether it changed something user-visible; if so
// the change is counted after all.
func (s *Store) UpdateQuiet(fn func(d *Data) (visible bool, err error)) error {
	visible := false
	return s.update(func(d *Data) error {
		var err error
		visible, err = fn(d)
		return err
	}, func() bool { return visible })
}

// row is one row to write; data is nil to delete it.
type row struct {
	key  rowKey
	data []byte
	w    *Workflow
	r    *AccessRequest
}

func (s *Store) update(fn func(d *Data) error, count func() bool) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	defer func() {
		if p := recover(); p != nil {
			s.rollback()
			panic(p)
		}
	}()
	err = fn(&s.d)
	if errors.Is(err, errNoChange) {
		return nil
	}
	var changed []row
	if err == nil {
		changed, err = s.diff()
	}
	if err == nil && len(changed) > 0 {
		err = s.write(changed)
	}
	if err != nil {
		return errors.Join(err, s.rollback())
	}
	for _, c := range changed {
		if c.data == nil {
			delete(s.saved, c.key)
		} else {
			s.saved[c.key] = c.data
		}
	}
	if len(changed) > 0 && count() {
		s.changes++
	}
	return nil
}

// rollback puts the working copy back to what is in the database. If that
// fails, the two could differ, so the store refuses further updates.
func (s *Store) rollback() error {
	d, err := s.decode()
	if err != nil {
		s.broken = fmt.Errorf("the store stopped saving after an error it could not undo (restart jitd): %w", err)
		return s.broken
	}
	s.d = d
	return nil
}

// diff returns the rows where the working copy differs from the database.
func (s *Store) diff() ([]row, error) {
	var out []row
	seen := make(map[rowKey]bool, len(s.d.Workflows)+len(s.d.Requests))
	add := func(k rowKey, v any, w *Workflow, r *AccessRequest) error {
		seen[k] = true
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if old, ok := s.saved[k]; !ok || !bytes.Equal(old, b) {
			out = append(out, row{key: k, data: b, w: w, r: r})
		}
		return nil
	}
	for id, w := range s.d.Workflows {
		if w == nil {
			return nil, fmt.Errorf("flow %s is nil", id)
		}
		if err := add(rowKey{"workflows", id}, w, w, nil); err != nil {
			return nil, err
		}
	}
	for id, r := range s.d.Requests {
		if r == nil {
			return nil, fmt.Errorf("request %s is nil", id)
		}
		if err := add(rowKey{"requests", id}, r, nil, r); err != nil {
			return nil, err
		}
	}
	for k := range s.saved {
		if !seen[k] {
			out = append(out, row{key: k})
		}
	}
	return out, nil
}

func (s *Store) write(changed []row) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range changed {
		var err error
		switch {
		case c.data == nil:
			// The table name is one of two constants, never input.
			_, err = tx.ExecContext(ctx, "DELETE FROM "+c.key.table+" WHERE id = ?", c.key.id)
		case c.w != nil:
			_, err = tx.ExecContext(ctx, `INSERT INTO workflows (id, name, data) VALUES (?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET name = excluded.name, data = excluded.data`,
				c.key.id, c.w.Name, string(c.data))
		default:
			_, err = tx.ExecContext(ctx, `INSERT INTO requests (id, workflow_id, requester, status, created_at, data)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET workflow_id = excluded.workflow_id, requester = excluded.requester,
					status = excluded.status, created_at = excluded.created_at, data = excluded.data`,
				c.key.id, c.r.WorkflowID, c.r.Requester.Login, string(c.r.Status),
				timeColumn(c.r.CreatedAt), string(c.data))
		}
		if err != nil {
			return fmt.Errorf("saving %s %s: %w", singular(c.key.table), c.key.id, err)
		}
	}
	return tx.Commit()
}

// Changes counts successful updates since the store was opened. Pages poll it
// to learn that something changed without reloading blindly.
func (s *Store) Changes() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changes
}

// createPrivate creates an empty file readable only by its owner. SQLite would
// create the database readable by everyone; its WAL and shared-memory files
// take their mode from the database file.
func createPrivate(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// removeDB removes a database file and its WAL and shared-memory files.
func removeDB(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		os.Remove(p)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		f.Sync()
		f.Close()
	}
}

// clone deep-copies v through JSON so callers never share store memory.
func clone[T any](v *T) *T {
	b, _ := json.Marshal(v)
	var out T
	json.Unmarshal(b, &out)
	return &out
}
