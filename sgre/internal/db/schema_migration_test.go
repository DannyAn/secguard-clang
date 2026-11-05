//go:build !nosqlite

package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestInitSchema_MigratesScanStatsAIStageStatus guards the additive
// scan_stats.ai_stage_status column: a pre-v0.7.4 database whose scan_stats
// lacks the column must be back-filled on upgrade, or ListScanStats /
// MarkAIStageDone / ListPerTypeStatus fail with "no such column" and the whole
// "dismissed not persisted" resume flow breaks.
func TestInitSchema_MigratesScanStatsAIStageStatus(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema (baseline): %v", err)
	}

	// Downgrade scan_stats to its pre-ai_stage_status form and seed one row.
	oldDDL := `
DROP TABLE scan_stats;
CREATE TABLE scan_stats (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL,
    vuln_type    TEXT NOT NULL,
    seed_count   INTEGER NOT NULL,
    final_count  INTEGER NOT NULL,
    filter_chain TEXT,
    created_at   INTEGER
);
INSERT INTO scan_stats (scan_id, vuln_type, seed_count, final_count, filter_chain)
    VALUES ('sc_old', 'null-deref', 10, 2, 'null-deref');
`
	if _, err := db.ExecContext(ctx, oldDDL); err != nil {
		t.Fatal(err)
	}

	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema (migration): %v", err)
	}

	// The column must now exist and default to 'pending' for the pre-existing row.
	var status string
	if err := db.QueryRowContext(ctx, `SELECT ai_stage_status FROM scan_stats WHERE scan_id = 'sc_old'`).Scan(&status); err != nil {
		t.Fatalf("ai_stage_status not migrated: %v", err)
	}
	if status != "pending" {
		t.Errorf("migrated ai_stage_status = %q, want 'pending'", status)
	}

	// MarkAIStageDone-equivalent UPDATE must succeed against the migrated column.
	if _, err := db.ExecContext(ctx, `UPDATE scan_stats SET ai_stage_status = 'done' WHERE scan_id = 'sc_old' AND vuln_type = 'null-deref'`); err != nil {
		t.Errorf("UPDATE ai_stage_status after migration: %v", err)
	}
}

// TestInitSchema_MigratesFindingLocIndexFunctionDrift pins the #217 identity
// migration: an older database whose uq_finding_loc still includes
// function_name can hold two rows for the same file:line:variable (a retry that
// omitted the function). InitSchema must collapse them (keep the newest) and
// rebuild the index on (scan_id, rule_id, file_path, line_number, variable), and
// normalize a NULL variable so the key can actually match it.
func TestInitSchema_MigratesFindingLocIndexFunctionDrift(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema (baseline): %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		DROP INDEX uq_finding_loc;
		CREATE UNIQUE INDEX uq_finding_loc ON findings(scan_id, rule_id, file_path, line_number, function_name, variable);
		INSERT INTO findings (id, rule_id, file_path, line_number, function_name, variable, status, scan_id, created_at) VALUES
			(1, 'CWE-476', 'a.c', 10, 'f1', 'p', 'confirmed', 'sc_old', 1),
			(2, 'CWE-476', 'a.c', 10, NULL, 'p', 'confirmed', 'sc_old', 2),
			(3, 'CWE-476', 'a.c', 20, 'f3', '', 'confirmed', 'sc_old', 3),
			(4, 'CWE-476', 'a.c', 20, 'f4', NULL, 'confirmed', 'sc_old', 4),
			(5, 'CWE-476', 'a.c', 10, 'f5', 'q', 'confirmed', 'sc_old', 5);
	`); err != nil {
		t.Fatal(err)
	}

	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema (migration): %v", err)
	}

	rows, err := db.QueryContext(ctx, `SELECT id, variable FROM findings ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []int64
	for rows.Next() {
		var id int64
		v := sql.NullString{}
		if err := rows.Scan(&id, &v); err != nil {
			t.Fatal(err)
		}
		if v.String == "" && !v.Valid {
			t.Errorf("finding %d still has a NULL variable; the key cannot match it", id)
		}
		got = append(got, id)
	}
	want := []int64{2, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("kept ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("kept ids = %v, want %v (newest row per new identity key)", got, want)
			break
		}
	}

	var sqlText string
	if err := db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'uq_finding_loc'`).Scan(&sqlText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sqlText, "function_name") || !strings.Contains(sqlText, "variable") {
		t.Errorf("uq_finding_loc not rebuilt on the new key: %s", sqlText)
	}
}
