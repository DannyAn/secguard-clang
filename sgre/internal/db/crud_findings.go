package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

var SupportedFindingCWEs = map[string]bool{
	"CWE-476": true,
	"CWE-787": true,
	"CWE-401": true,
	"CWE-78":  true,
	"CWE-89":  true,
	"CWE-404": true,
	"CWE-457": true,
	"CWE-416": true,
	"CWE-415": true,
	"CWE-134": true,
	"CWE-190": true,
	"CWE-362": true,
	"CWE-798": true,
	"CWE-667": true,
	"CWE-327": true,
}

func (s *store) InsertFinding(ctx context.Context, f *Finding) (int64, error) {
	cweNorm := strings.ToUpper(strings.TrimSpace(f.RuleID))
	if cweNorm != "" && !SupportedFindingCWEs[cweNorm] {
		return 0, fmt.Errorf("db: insert finding: unsupported rule_id %q (not a pipeline-detected vulnerability type)", f.RuleID)
	}
	if f.Status == "" {
		f.Status = "open"
	}
	if f.CreatedAt == 0 {
		f.CreatedAt = now()
	}
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO findings (rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, scan_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.RuleID, f.Severity, f.Confidence, f.Evidence, f.Status, f.FilePath, f.LineNumber, f.FunctionName, f.Properties, f.ScanID, f.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("db: insert finding: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert finding: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) ListFindings(ctx context.Context) ([]*Finding, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, scan_id, created_at FROM findings ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: list findings: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (s *store) ListFindingsByStatus(ctx context.Context, status string) ([]*Finding, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, scan_id, created_at FROM findings WHERE status = ? ORDER BY id`, status)
	if err != nil {
		return nil, fmt.Errorf("db: list findings by status: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func scanFindings(rows *sql.Rows) ([]*Finding, error) {
	var findings []*Finding
	for rows.Next() {
		f := &Finding{}
		var scanID sql.NullString
		if err := rows.Scan(&f.ID, &f.RuleID, &f.Severity, &f.Confidence, &f.Evidence, &f.Status, &f.FilePath, &f.LineNumber, &f.FunctionName, &f.Properties, &scanID, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan finding: %w", err)
		}
		f.ScanID = scanID.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
