package db

import (
	"context"
	"database/sql"
	"fmt"
)

func migrateSchema(ctx context.Context, db *sql.DB) error {
	if err := migrateFindingsTable(ctx, db); err != nil {
		return fmt.Errorf("migrate findings: %w", err)
	}
	if err := migrateSecurityEventsTable(ctx, db); err != nil {
		return fmt.Errorf("migrate security events: %w", err)
	}
	if err := migrateGraphEdgesTable(ctx, db); err != nil {
		return fmt.Errorf("migrate graph edges: %w", err)
	}
	return nil
}

// migrateGraphEdgesTable recreates graph_edges when its edge_type CHECK
// constraint predates the inter-procedural edge types (PARAM_BINDING / RETURN,
// added when the semantic graph grew parameter-argument and return-value edges).
// SQLite cannot ALTER a CHECK constraint, so the table is rebuilt preserving rows.
func migrateGraphEdgesTable(ctx context.Context, db *sql.DB) error {
	var tableExists bool
	err := db.QueryRowContext(ctx,
		"SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name='graph_edges'",
	).Scan(&tableExists)
	if err != nil {
		return err
	}
	if !tableExists {
		return nil
	}

	var createSQL string
	if err := db.QueryRowContext(ctx,
		"SELECT sql FROM sqlite_master WHERE type='table' AND name='graph_edges'",
	).Scan(&createSQL); err != nil {
		return err
	}
	// The current constraint has PARAM_BINDING/RETURN and no longer carries the
	// unused BRANCH edge type; any other shape is rebuilt.
	if contains(createSQL, "'PARAM_BINDING'") && contains(createSQL, "'RETURN'") && !contains(createSQL, "'BRANCH'") {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	steps := []string{
		`ALTER TABLE graph_edges RENAME TO graph_edges_old`,
		`CREATE TABLE graph_edges (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			src_id      INTEGER NOT NULL,
			dst_id      INTEGER NOT NULL,
			edge_type   TEXT NOT NULL CHECK (edge_type IN (
				'CALL', 'DATA_FLOW', 'OWNERSHIP_TRANSFER', 'RELEASE', 'ALIAS',
				'PARAM_BINDING', 'RETURN'
			)),
			properties  TEXT,
			FOREIGN KEY(src_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
			FOREIGN KEY(dst_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
		)`,
		`INSERT INTO graph_edges (id, src_id, dst_id, edge_type, properties)
		 SELECT id, src_id, dst_id, edge_type, properties FROM graph_edges_old`,
		`DROP TABLE graph_edges_old`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(src_id)`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(dst_id)`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges(edge_type)`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_src_type ON graph_edges(src_id, edge_type)`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_dst_type ON graph_edges(dst_id, edge_type)`,
	}

	for _, sql := range steps {
		if _, err := tx.ExecContext(ctx, sql); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// migrateSecurityEventsTable recreates the security_events table when its
// event_type CHECK constraint predates the newer event types (added when new
// detectors were introduced). SQLite cannot ALTER a CHECK constraint, so the
// table is rebuilt in place, preserving any existing rows.
func migrateSecurityEventsTable(ctx context.Context, db *sql.DB) error {
	var tableExists bool
	err := db.QueryRowContext(ctx,
		"SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name='security_events'",
	).Scan(&tableExists)
	if err != nil {
		return err
	}
	if !tableExists {
		return nil
	}

	var createSQL string
	if err := db.QueryRowContext(ctx,
		"SELECT sql FROM sqlite_master WHERE type='table' AND name='security_events'",
	).Scan(&createSQL); err != nil {
		return err
	}
	// SIGNED_COMPARE is the newest event type — its presence means the
	// security_events CHECK constraint is already current. Earlier sentinels
	// (e.g. DIVIDE_BY_ZERO) would falsely report "current" on DBs created
	// after DIVIDE_BY_ZERO but before SIGNED_COMPARE was added, silently
	// rejecting SIGNED_COMPARE event inserts.
	if contains(createSQL, "'SIGNED_COMPARE'") {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	steps := []string{
		`ALTER TABLE security_events RENAME TO security_events_old`,
		`CREATE TABLE security_events (
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
		)`,
		`INSERT INTO security_events (id, event_type, entity_id, location_id, properties)
		 SELECT id, event_type, entity_id, location_id, properties FROM security_events_old`,
		`DROP TABLE security_events_old`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_entity ON security_events(entity_id)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_location ON security_events(location_id)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_type_entity ON security_events(event_type, entity_id)`,
	}

	for _, sql := range steps {
		if _, err := tx.ExecContext(ctx, sql); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func migrateFindingsTable(ctx context.Context, db *sql.DB) error {
	var tableExists bool
	err := db.QueryRowContext(ctx,
		"SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name='findings'",
	).Scan(&tableExists)
	if err != nil {
		return err
	}
	if !tableExists {
		return nil
	}

	columns, err := getTableColumns(ctx, db, "findings")
	if err != nil {
		return err
	}

	hasFilePath := false
	hasLineNumber := false
	hasFunctionName := false
	hasProperties := false
	hasScanID := false
	for _, col := range columns {
		switch col {
		case "file_path":
			hasFilePath = true
		case "line_number":
			hasLineNumber = true
		case "function_name":
			hasFunctionName = true
		case "properties":
			hasProperties = true
		case "scan_id":
			hasScanID = true
		}
	}

	if !hasFilePath {
		if _, err := db.ExecContext(ctx, "ALTER TABLE findings ADD COLUMN file_path TEXT"); err != nil {
			return err
		}
	}
	if !hasLineNumber {
		if _, err := db.ExecContext(ctx, "ALTER TABLE findings ADD COLUMN line_number INTEGER"); err != nil {
			return err
		}
	}
	if !hasFunctionName {
		if _, err := db.ExecContext(ctx, "ALTER TABLE findings ADD COLUMN function_name TEXT"); err != nil {
			return err
		}
	}
	if !hasProperties {
		if _, err := db.ExecContext(ctx, "ALTER TABLE findings ADD COLUMN properties TEXT"); err != nil {
			return err
		}
	}
	if !hasScanID {
		if _, err := db.ExecContext(ctx, "ALTER TABLE findings ADD COLUMN scan_id TEXT"); err != nil {
			return err
		}
	}

	needsRecreate := false
	var statusCheck string
	err = db.QueryRowContext(ctx,
		"SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'",
	).Scan(&statusCheck)
	if err == nil {
		if !contains(statusCheck, "suspected") {
			needsRecreate = true
		}
	}

	if needsRecreate {
		if err := recreateFindingsTable(ctx, db); err != nil {
			return err
		}
	}

	return nil
}

func recreateFindingsTable(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	steps := []string{
		`ALTER TABLE findings RENAME TO findings_old`,
		`CREATE TABLE findings (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id       TEXT NOT NULL,
			severity      TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
			confidence    REAL CHECK (confidence >= 0.0 AND confidence <= 1.0),
			evidence      TEXT,
			status        TEXT DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'suspected', 'dismissed')),
			file_path     TEXT,
			line_number   INTEGER,
			function_name TEXT,
			properties    TEXT,
			scan_id       TEXT,
			created_at    INTEGER
		)`,
		`INSERT INTO findings (id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, scan_id, created_at)
		 SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, scan_id, created_at FROM findings_old`,
		`DROP TABLE findings_old`,
		`CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path)`,
	}

	for _, sql := range steps {
		if _, err := tx.ExecContext(ctx, sql); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func getTableColumns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	row := db.QueryRowContext(ctx,
		"SELECT group_concat(name, ',') FROM pragma_table_info(?)", table,
	)

	var csv string
	if err := row.Scan(&csv); err != nil {
		return nil, err
	}

	if csv == "" {
		return nil, nil
	}

	var columns []string
	current := ""
	for _, c := range csv {
		if c == ',' {
			columns = append(columns, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		columns = append(columns, current)
	}
	return columns, nil
}
