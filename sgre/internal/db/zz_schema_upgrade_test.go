//go:build !nosqlite

package db

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// A pre-existing sgre.db created with the OLD event_type / settlement status
// enums must be upgraded by InitSchema: the old CHECK would otherwise reject
// every newly emitted event (the production "CHECK constraint failed" outage).
func TestInitSchemaUpgradesDriftedEnums(t *testing.T) {
	ctx := context.Background()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.ExecContext(ctx, `
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL CHECK (event_type IN ('NULL_VALUE','DEREFERENCE','CONTRACT_GAP')),
    entity_id INTEGER, location_id INTEGER, properties TEXT
);
CREATE TABLE settlement_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL, vuln_type TEXT NOT NULL, range_str TEXT NOT NULL DEFAULT 'all',
    subagent_id TEXT NOT NULL, written INTEGER NOT NULL DEFAULT 0, dismissed INTEGER NOT NULL DEFAULT 0,
    evidence_opens INTEGER NOT NULL DEFAULT 0, source_reads INTEGER NOT NULL DEFAULT 0,
    repo_greps INTEGER NOT NULL DEFAULT 0, needs_context INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'done' CHECK (status IN ('dispatched','done','failed')),
    retry_count INTEGER NOT NULL DEFAULT 0, wall_ms INTEGER, created_at INTEGER
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT, vuln_type TEXT, severity TEXT,
    confidence REAL, evidence TEXT, status TEXT, file_path TEXT, line_number INTEGER,
    function_name TEXT, variable TEXT, properties TEXT, summary TEXT, reasoning TEXT,
    fix_strategy TEXT, exception_check TEXT, review_status TEXT, review_reasoning TEXT,
    scan_id TEXT, fingerprint TEXT, created_at INTEGER
);
INSERT INTO findings (rule_id, status, severity, file_path, scan_id, fingerprint) VALUES ('CWE-476', 'confirmed', 'high', 'a.c', 'sc_u', 'fp1');
`); err != nil {
		t.Fatal(err)
	}

	if err := InitSchema(ctx, d); err != nil {
		t.Fatalf("InitSchema on a drifted DB: %v", err)
	}

	for _, et := range []string{"STACK_ESCAPE", "INVALID_FREE", "SWITCH_FLOW", "UNBOUNDED_LENGTH"} {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO security_events (event_type, entity_id, location_id, properties) VALUES (?, NULL, NULL, '{}')`, et); err != nil {
			t.Errorf("event_type %s must be accepted after the upgrade: %v", et, err)
		}
	}
	for i, status := range []string{"partial", "released"} {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO settlement_stats (scan_id, vuln_type, range_str, subagent_id, status, created_at)
			 VALUES ('sc_u', 'null-deref', ?, 'h', ?, 0)`, fmt.Sprintf("r%d", i), status); err != nil {
			t.Errorf("settlement status %s must be accepted after the upgrade: %v", status, err)
		}
	}
	if _, err := d.ExecContext(ctx,
		`UPDATE settlement_stats SET heartbeat_at = 123 WHERE scan_id = 'sc_u'`); err != nil {
		t.Errorf("heartbeat_at column must exist after the upgrade: %v", err)
	}

	// Other tables' data is NOT dropped by the targeted upgrade.
	var n int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&n); err != nil || n != 1 {
		t.Errorf("unrelated findings rows must survive the targeted upgrade: n=%d err=%v", n, err)
	}
}
