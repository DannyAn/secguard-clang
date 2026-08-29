package db

import (
	"context"
	"database/sql"
	"fmt"
)

const SchemaDDL = `
-- Pragmas
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- ============================================================
-- Layer 1: Program Facts (most stable, vulnerability-agnostic)
-- ============================================================

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    path        TEXT NOT NULL UNIQUE,
    language    TEXT DEFAULT 'c',
    checksum    TEXT,
    loc         INTEGER,
    created_at  INTEGER
);

CREATE TABLE IF NOT EXISTS functions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      INTEGER NOT NULL,
    name         TEXT,
    signature    TEXT,
    return_type  TEXT,
    is_static    BOOLEAN,
    start_line   INTEGER,
    end_line     INTEGER,
    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS variables (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id      INTEGER,
    name             TEXT,
    type             TEXT,
    storage_class    TEXT DEFAULT 'auto' CHECK (storage_class IN ('auto', 'static', 'register', 'heap')),
    declaration_line INTEGER,
    is_pointer       BOOLEAN,
    is_nullable      BOOLEAN,
    source_kind      TEXT,
    FOREIGN KEY(function_id) REFERENCES functions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS expressions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id  INTEGER,
    text         TEXT,
    line         INTEGER,
    expr_type    TEXT,
    FOREIGN KEY(function_id) REFERENCES functions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS types (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL,
    kind  TEXT
);

CREATE TABLE IF NOT EXISTS locations (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id  INTEGER NOT NULL,
    line     INTEGER,
    column   INTEGER,
    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- ============================================================
-- Layer 2: Semantic Graph (unified graph model)
-- ============================================================

CREATE TABLE IF NOT EXISTS graph_nodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id   INTEGER NOT NULL,
    properties  TEXT,
    UNIQUE(entity_type, entity_id, properties)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    src_id      INTEGER NOT NULL,
    dst_id      INTEGER NOT NULL,
    edge_type   TEXT NOT NULL CHECK (edge_type IN (
        'CALL', 'DATA_FLOW', 'OWNERSHIP_TRANSFER', 'RELEASE', 'ALIAS',
        'PARAM_BINDING', 'RETURN', 'LOCK_ORDER', 'GLOBAL_ACCESS'
    )),
    properties  TEXT,
    FOREIGN KEY(src_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(dst_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
);

-- ============================================================
-- Layer 3: Security Evidence (unified event model)
-- ============================================================

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL CHECK (event_type IN (
        'NULL_VALUE', 'DEREFERENCE', 'NULL_GUARD',
        'MEMORY_ALLOC', 'MEMORY_RELEASE',
        'RESOURCE_ACQUIRE', 'RESOURCE_RELEASE',
        'VARIABLE_DECLARE', 'VALUE_USE', 'VALUE_INIT',
        'BUFFER_ACCESS', 'INTEGER_OP', 'INJECTION',
        'USE_AFTER_FREE', 'DOUBLE_FREE', 'FORMAT_STRING',
        'INTEGER_OVERFLOW', 'RACE_CONDITION', 'HARDCODED_SECRET',
        'DEADLOCK', 'CRYPTO_MISUSE',
        'DIVIDE_BY_ZERO', 'UNCHECKED_RETURN', 'PATH_TRAVERSAL',
        'SIZEOF_MISUSE', 'SIGNED_COMPARE'
    )),
    entity_id   INTEGER,
    location_id INTEGER,
    properties  TEXT,
    FOREIGN KEY(location_id) REFERENCES locations(id) ON DELETE SET NULL
);

-- ============================================================
-- Layer 4: Findings (AI Agent output, most variable)
-- ============================================================

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         TEXT NOT NULL,
    severity        TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence      REAL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence        TEXT,
    status          TEXT DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'suspected', 'dismissed', 'auto-confirmed')),
    file_path       TEXT,
    line_number     INTEGER,
    function_name   TEXT,
    properties      TEXT,
    summary         TEXT,
    reasoning       TEXT,
    fix_strategy    TEXT,
    exception_check TEXT,
    review_status   TEXT CHECK (review_status IS NULL OR review_status = '' OR review_status IN ('confirmed', 'dismissed', 'suspected-kept')),
    review_reasoning TEXT,
    scan_id         TEXT,
    fingerprint     TEXT,
    created_at      INTEGER
);

-- ============================================================
-- Scan Stats (pipeline statistics per scan per vulnerability type)
-- ============================================================

CREATE TABLE IF NOT EXISTS scan_stats (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    seed_count    INTEGER NOT NULL,
    final_count   INTEGER NOT NULL,
    filter_chain  TEXT,
    created_at    INTEGER
);

-- ============================================================
-- Review Sessions (incremental PR/MR review anchor)
-- ============================================================

-- A review session is the stable, content-addressed anchor for an incremental
-- review. review_id is derived deterministically from (kind, base_sha, head_sha)
-- so re-running the same diff is idempotent; a new head commit produces a new
-- review while the base stays fixed, so only lines newly changed since base are
-- reported as new findings.
CREATE TABLE IF NOT EXISTS review_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id     TEXT NOT NULL UNIQUE,
    kind          TEXT NOT NULL CHECK (kind IN ('diff', 'pr', 'mr')),
    base_ref      TEXT NOT NULL,
    head_ref      TEXT NOT NULL,
    base_sha      TEXT NOT NULL,
    head_sha      TEXT NOT NULL,
    changed_files TEXT,
    status        TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'failed')),
    created_at    INTEGER,
    updated_at    INTEGER
);

-- ============================================================
-- Function Summary (AI Agent key input)
-- ============================================================

CREATE TABLE IF NOT EXISTS function_summary (
    function_id        INTEGER PRIMARY KEY,
    return_nullable    BOOLEAN,
    parameter_nullable TEXT,
    side_effect        TEXT,
    summary_json       TEXT,
    FOREIGN KEY(function_id) REFERENCES functions(id) ON DELETE CASCADE
);

-- ============================================================
-- Performance Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_checksum ON files(checksum);

CREATE INDEX IF NOT EXISTS idx_functions_file_id ON functions(file_id);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);

CREATE INDEX IF NOT EXISTS idx_variables_function_id ON variables(function_id);
CREATE INDEX IF NOT EXISTS idx_variables_is_pointer ON variables(is_pointer);
CREATE INDEX IF NOT EXISTS idx_variables_storage_class ON variables(storage_class);

CREATE INDEX IF NOT EXISTS idx_expressions_function_id ON expressions(function_id);

CREATE INDEX IF NOT EXISTS idx_locations_file_id ON locations(file_id);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_entity ON graph_nodes(entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(src_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(dst_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges(edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_src_type ON graph_edges(src_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_dst_type ON graph_edges(dst_id, edge_type);

CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_entity ON security_events(entity_id);
CREATE INDEX IF NOT EXISTS idx_security_events_location ON security_events(location_id);
CREATE INDEX IF NOT EXISTS idx_security_events_type_entity ON security_events(event_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
-- Idempotency key for UpsertFinding: one row per (scan, CWE, location). This is
-- what makes concurrent --write-json upserts atomic (the ON CONFLICT target).
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_loc ON findings(scan_id, rule_id, file_path, line_number, function_name);

CREATE INDEX IF NOT EXISTS idx_scan_stats_scan_id ON scan_stats(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_stats_vuln_type ON scan_stats(vuln_type);
`

func InitSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, SchemaDDL); err != nil {
		return fmt.Errorf("db: init schema: exec ddl: %w", err)
	}
	// Migrate pre-existing databases that predate the incremental-review schema:
	// findings.fingerprint is additive, so an old sgre.db (whose findings table
	// was created without the column) needs the column back-filled as NULL before
	// any fingerprint-aware query can run. IF NOT EXISTS-style guards are not
	// available for ADD COLUMN in SQLite, so check pragma table_info first.
	if err := ensureColumn(ctx, db, "findings", "fingerprint", "TEXT"); err != nil {
		return fmt.Errorf("db: init schema: ensure findings.fingerprint: %w", err)
	}
	return nil
}

// ensureColumn adds a column to a table when it is missing. It is the idempotent
// migration primitive for additive columns that CREATE TABLE IF NOT EXISTS
// cannot back-fill on an already-existing table.
func ensureColumn(ctx context.Context, db *sql.DB, table, column, decl string) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return fmt.Errorf("db: ensure column: pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("db: ensure column: scan pragma row: %w", err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("db: ensure column: pragma rows: %w", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+decl); err != nil {
		return fmt.Errorf("db: ensure column: alter table %s add %s: %w", table, column, err)
	}
	return nil
}
