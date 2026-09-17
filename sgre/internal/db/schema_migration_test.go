//go:build !nosqlite

package db

import (
	"context"
	"database/sql"
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
