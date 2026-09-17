//go:build !nosqlite

package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestInitSchema_MigratesStaleCheckConstraints guards the CHECK-constraint
// migration: a database created before v0.5.0 (findings.status CHECK lacks
// 'auto-confirmed', security_events.event_type CHECK lacks DANGEROUS_FUNCTION,
// and findings predates the fingerprint/variable columns) must be rebuilt so the
// newer writes succeed and existing rows survive the copy.
func TestInitSchema_MigratesStaleCheckConstraints(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Establish the current schema first so the surrounding tables (files,
	// locations, graph, …) exist in their current shape; the test then downgrades
	// ONLY findings + security_events to their pre-v0.5.0 CHECK-limited forms.
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema (baseline): %v", err)
	}

	oldDDL := `
DROP TABLE findings;
DROP TABLE security_events;
CREATE TABLE findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         TEXT NOT NULL,
    severity        TEXT,
    confidence      REAL,
    evidence        TEXT,
    status          TEXT DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'suspected', 'dismissed')),
    file_path       TEXT,
    line_number     INTEGER,
    function_name   TEXT,
    properties      TEXT,
    summary         TEXT,
    reasoning       TEXT,
    fix_strategy    TEXT,
    exception_check TEXT,
    review_status   TEXT,
    review_reasoning TEXT,
    scan_id         TEXT,
    created_at      INTEGER
);
CREATE TABLE security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL CHECK (event_type IN ('NULL_VALUE', 'DEREFERENCE')),
    entity_id   INTEGER,
    location_id INTEGER,
    properties  TEXT,
    FOREIGN KEY(location_id) REFERENCES locations(id) ON DELETE SET NULL
);
INSERT INTO findings (rule_id, severity, status, file_path, line_number, function_name, summary, scan_id)
    VALUES ('CWE-476', 'high', 'confirmed', 'src/a.c', 10, 'f', 'kept row', 'sc_x');
`
	if _, err := db.ExecContext(ctx, oldDDL); err != nil {
		t.Fatal(err)
	}

	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema (migration): %v", err)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO findings (rule_id, status) VALUES ('CWE-476', 'auto-confirmed')`); err != nil {
		t.Errorf("auto-confirmed status rejected after migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO security_events (event_type) VALUES ('DANGEROUS_FUNCTION')`); err != nil {
		t.Errorf("DANGEROUS_FUNCTION event rejected after migration: %v", err)
	}

	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE function_name = 'f' AND summary = 'kept row'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("pre-existing findings row lost in rebuild: count=%d err=%v", n, err)
	}

	var idxSQL string
	if err := db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'uq_finding_loc'`).Scan(&idxSQL); err != nil || !strings.Contains(idxSQL, "variable") {
		t.Errorf("uq_finding_loc index missing variable column: sql=%q err=%v", idxSQL, err)
	}
}
