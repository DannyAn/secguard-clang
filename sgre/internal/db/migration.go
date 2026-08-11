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
	return nil
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
