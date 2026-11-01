package db

import (
	"context"
	"fmt"
)

// UpsertCandidateVerdict records an AI verdict on a candidate (P0-1). It is the
// dismissed-only ledger: a dismissed verdict is idempotently recorded so the
// orchestrator can tell "classified and dismissed" from "never classified".
func (s *store) UpsertCandidateVerdict(ctx context.Context, v *CandidateVerdict) (int64, error) {
	var id int64
	err := s.exec.QueryRowContext(ctx, `
		INSERT INTO candidate_verdicts
			(scan_id, vuln_type, file_path, line_number, function_name, variable, verdict, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, vuln_type, file_path, line_number, function_name)
		DO UPDATE SET variable = excluded.variable, verdict = excluded.verdict, reason = excluded.reason
		RETURNING id`, v.ScanID, v.VulnType, v.FilePath, v.LineNumber, v.FunctionName, v.Variable, v.Verdict, v.Reason).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("db: upsert candidate verdict: %w", err)
	}
	return id, nil
}

// CountCandidateVerdictsByType returns the dismissed count per vuln type for a
// scan, keyed by vuln type. It is the dismissed half of the recovery ledger.
func (s *store) CountCandidateVerdictsByType(ctx context.Context, scanID string) (map[string]int, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT vuln_type, COUNT(*) FROM candidate_verdicts WHERE scan_id = ? GROUP BY vuln_type`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: count candidate verdicts: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var typ string
		var n int
		if err := rows.Scan(&typ, &n); err != nil {
			return nil, fmt.Errorf("db: scan candidate verdict count: %w", err)
		}
		out[typ] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: candidate verdict rows: %w", err)
	}
	return out, nil
}
