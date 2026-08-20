package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// SupportedFindingCWEs is the set of CWE rule_ids the pipeline can detect and
// therefore persist as findings. It is seeded with a built-in default for
// standalone db-package tests; cli/root.go overrides it at startup with
// planner.AllCWEs() so the set always matches the live registry — never edit
// this default map by hand when adding a vuln type, only add the CWE to the
// VulnTypeSpec in planner/registry.go.
var SupportedFindingCWEs = map[string]bool{
	"CWE-476": true, // null-deref
	"CWE-787": true, // buffer-overflow
	"CWE-125": true, // out-of-bounds
	"CWE-401": true, // memory-leak
	"CWE-78":  true, // injection (command)
	"CWE-89":  true, // injection (SQL, legacy)
	"CWE-404": true, // resource-leak
	"CWE-457": true, // uninit
	"CWE-416": true, // use-after-free
	"CWE-415": true, // double-free
	"CWE-134": true, // format-string
	"CWE-190": true, // integer-overflow
	"CWE-362": true, // race-condition
	"CWE-798": true, // hardcoded-secret
	"CWE-667": true, // deadlock
	"CWE-327": true, // crypto-misuse
	"CWE-326": true, // crypto-misuse (legacy: weak algorithm)
	"CWE-338": true, // crypto-misuse (legacy: weak PRNG)
	"CWE-369": true, // divide-by-zero
	"CWE-252": true, // unchecked-return
	"CWE-22":  true, // path-traversal
	"CWE-681": true, // signed-compare
	"CWE-467": true, // sizeof-misuse
}

// SetSupportedCWEs replaces the supported-CWE set at CLI startup with the
// planner-derived set, so the db layer never drifts from the registry. Must
// be called exactly once before any InsertFinding call, from the main goroutine
// (not concurrently with finding writes).
func SetSupportedCWEs(cwes map[string]bool) {
	SupportedFindingCWEs = cwes
}

// SupportedCWEsList returns the sorted, comma-joined list of supported CWEs for
// error messages. Single source of truth, so it can never drift from the map.
func SupportedCWEsList() string {
	list := make([]string, 0, len(SupportedFindingCWEs))
	for cwe := range SupportedFindingCWEs {
		list = append(list, cwe)
	}
	sort.Strings(list)
	return strings.Join(list, ", ")
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
		`INSERT INTO findings (rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, summary, reasoning, fix_strategy, exception_check, review_status, review_reasoning, scan_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.RuleID, f.Severity, f.Confidence, f.Evidence, f.Status, f.FilePath, f.LineNumber, f.FunctionName, f.Properties, f.Summary, f.Reasoning, f.FixStrategy, f.ExceptionCheck, f.ReviewStatus, f.ReviewReasoning, f.ScanID, f.CreatedAt)
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
		`SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, summary, reasoning, fix_strategy, exception_check, review_status, review_reasoning, scan_id, created_at FROM findings ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: list findings: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (s *store) ListFindingsByStatus(ctx context.Context, status string) ([]*Finding, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, summary, reasoning, fix_strategy, exception_check, review_status, review_reasoning, scan_id, created_at FROM findings WHERE status = ? ORDER BY id`, status)
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
		if err := rows.Scan(&f.ID, &f.RuleID, &f.Severity, &f.Confidence, &f.Evidence, &f.Status, &f.FilePath, &f.LineNumber, &f.FunctionName, &f.Properties, &f.Summary, &f.Reasoning, &f.FixStrategy, &f.ExceptionCheck, &f.ReviewStatus, &f.ReviewReasoning, &scanID, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan finding: %w", err)
		}
		f.ScanID = scanID.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (s *store) GetFindingByID(ctx context.Context, id int64) (*Finding, error) {
	row := s.exec.QueryRowContext(ctx,
		`SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, summary, reasoning, fix_strategy, exception_check, review_status, review_reasoning, scan_id, created_at FROM findings WHERE id = ?`, id)
	f := &Finding{}
	var scanID sql.NullString
	if err := row.Scan(&f.ID, &f.RuleID, &f.Severity, &f.Confidence, &f.Evidence, &f.Status, &f.FilePath, &f.LineNumber, &f.FunctionName, &f.Properties, &f.Summary, &f.Reasoning, &f.FixStrategy, &f.ExceptionCheck, &f.ReviewStatus, &f.ReviewReasoning, &scanID, &f.CreatedAt); err != nil {
		return nil, fmt.Errorf("db: get finding by id: %w", err)
	}
	f.ScanID = scanID.String
	return f, nil
}

// UpdateFindingReview records the second-round confirmation result for a
// suspected finding: review_status is confirmed/dismissed/suspected-kept,
// review_reasoning is the AI's justification for the second-round call.
func (s *store) UpdateFindingReview(ctx context.Context, id int64, reviewStatus, reviewReasoning string) error {
	res, err := s.exec.ExecContext(ctx,
		`UPDATE findings SET review_status = ?, review_reasoning = ? WHERE id = ?`,
		reviewStatus, reviewReasoning, id)
	if err != nil {
		return fmt.Errorf("db: update finding review: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("db: update finding review: no finding with id %d", id)
	}
	return nil
}
