package migrate

import (
	"database/sql"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// fixtureFS returns a two-migration source: create a table, then add a column.
func fixtureFS() fstest.MapFS {
	return fstest.MapFS{
		"000001_create_widgets.up.sql":   {Data: []byte(`CREATE TABLE widgets (id INTEGER PRIMARY KEY);`)},
		"000001_create_widgets.down.sql": {Data: []byte(`DROP TABLE widgets;`)},
		"000002_add_name.up.sql":         {Data: []byte(`ALTER TABLE widgets ADD COLUMN name TEXT;`)},
		"000002_add_name.down.sql":       {Data: []byte(`ALTER TABLE widgets DROP COLUMN name;`)},
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	// A shared-cache in-memory DB tied to the test; closed on cleanup.
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestUpAppliesAll(t *testing.T) {
	db := openDB(t)
	r, err := New(db, fixtureFS())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	if err := r.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	v, dirty, err := r.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v != 2 || dirty {
		t.Errorf("Version = %d dirty=%v, want 2 false", v, dirty)
	}
	// Both columns must exist.
	if _, err := db.Exec(`INSERT INTO widgets (id, name) VALUES (1, 'a');`); err != nil {
		t.Errorf("insert after migrate failed: %v", err)
	}
}

func TestUpIsIdempotent(t *testing.T) {
	db := openDB(t)
	r, _ := New(db, fixtureFS())
	defer r.Close()
	if err := r.Up(); err != nil {
		t.Fatalf("Up #1: %v", err)
	}
	if err := r.Up(); err != nil {
		t.Fatalf("Up #2 (no change) should be nil, got %v", err)
	}
}

func TestFreshVersionIsZero(t *testing.T) {
	db := openDB(t)
	r, _ := New(db, fixtureFS())
	defer r.Close()
	v, dirty, err := r.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v != 0 || dirty {
		t.Errorf("fresh Version = %d dirty=%v, want 0 false", v, dirty)
	}
}

func TestStepsUpThenDown(t *testing.T) {
	db := openDB(t)
	r, _ := New(db, fixtureFS())
	defer r.Close()

	if err := r.Steps(1); err != nil {
		t.Fatalf("Steps(1): %v", err)
	}
	if v, _, _ := r.Version(); v != 1 {
		t.Errorf("after Steps(1) version = %d, want 1", v)
	}
	if err := r.Steps(-1); err != nil {
		t.Fatalf("Steps(-1): %v", err)
	}
	if v, _, _ := r.Version(); v != 0 {
		t.Errorf("after Steps(-1) version = %d, want 0", v)
	}
}

func TestDownAll(t *testing.T) {
	db := openDB(t)
	r, _ := New(db, fixtureFS())
	defer r.Close()
	if err := r.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := r.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if v, _, _ := r.Version(); v != 0 {
		t.Errorf("after Down version = %d, want 0", v)
	}
}

func TestForceClearsDirty(t *testing.T) {
	db := openDB(t)
	r, _ := New(db, fixtureFS())
	defer r.Close()
	if err := r.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := r.Force(1); err != nil {
		t.Fatalf("Force: %v", err)
	}
	if v, dirty, _ := r.Version(); v != 1 || dirty {
		t.Errorf("after Force(1) = %d dirty=%v, want 1 false", v, dirty)
	}
}
