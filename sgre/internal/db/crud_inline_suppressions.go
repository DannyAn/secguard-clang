package db

import (
	"context"
	"database/sql"
	"fmt"
)

// ReplaceInlineSuppressions atomically replaces a file's suppression rows with
// the freshly-collected set. The indexer rebuilds a file's rows on every
// checksum change, so delete-then-insert (not upsert) keeps the table in lockstep
// with the current source (a deleted suppression comment must not linger).
func (s *store) ReplaceInlineSuppressions(ctx context.Context, fileID int64, suppressions []InlineSuppression) error {
	if _, err := s.exec.ExecContext(ctx, `DELETE FROM inline_suppressions WHERE file_id = ?`, fileID); err != nil {
		return fmt.Errorf("db: delete inline suppressions: %w", err)
	}
	for _, sup := range suppressions {
		if _, err := s.exec.ExecContext(ctx,
			`INSERT INTO inline_suppressions (file_id, line, vuln_type, reason) VALUES (?, ?, ?, ?)`,
			fileID, sup.Line, sup.VulnType, sup.Reason); err != nil {
			return fmt.Errorf("db: insert inline suppression: %w", err)
		}
	}
	return nil
}

// ListInlineSuppressions returns every suppression directive, keyed by nothing
// (the caller indexes by file/line). It is the planner filter's input.
func (s *store) ListInlineSuppressions(ctx context.Context) ([]InlineSuppression, error) {
	out, err := queryList(ctx, s.exec,
		`SELECT id, file_id, line, vuln_type, reason FROM inline_suppressions`, nil,
		func(rows *sql.Rows) (InlineSuppression, error) {
			var sup InlineSuppression
			var reason *string
			if err := rows.Scan(&sup.ID, &sup.FileID, &sup.Line, &sup.VulnType, &reason); err != nil {
				return InlineSuppression{}, err
			}
			if reason != nil {
				sup.Reason = *reason
			}
			return sup, nil
		})
	if err != nil {
		return nil, fmt.Errorf("db: list inline suppressions: %w", err)
	}
	return out, nil
}
