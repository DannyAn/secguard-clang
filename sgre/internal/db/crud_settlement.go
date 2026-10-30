package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) UpsertSettlementStat(ctx context.Context, st *SettlementStat) error {
	if st.CreatedAt == 0 {
		st.CreatedAt = now()
	}
	if st.Status == "" {
		st.Status = "done"
	}
	var wallMS interface{}
	if st.WallMS > 0 {
		wallMS = st.WallMS
	}
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO settlement_stats (scan_id, vuln_type, range_str, subagent_id, written, dismissed, evidence_opens, source_reads, repo_greps, needs_context, status, retry_count, wall_ms, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id, vuln_type, range_str, subagent_id) DO UPDATE SET
		   written = excluded.written,
		   dismissed = excluded.dismissed,
		   evidence_opens = excluded.evidence_opens,
		   source_reads = excluded.source_reads,
		   repo_greps = excluded.repo_greps,
		   needs_context = excluded.needs_context,
		   status = excluded.status,
		   retry_count = excluded.retry_count,
		   wall_ms = excluded.wall_ms,
		   created_at = excluded.created_at`,
		st.ScanID, st.VulnType, st.RangeStr, st.SubagentID,
		st.Written, st.Dismissed, st.EvidenceOpens, st.SourceReads, st.RepoGreps, st.NeedsContext,
		st.Status, st.RetryCount, wallMS, st.CreatedAt)
	if err != nil {
		return fmt.Errorf("db: upsert settlement stat: %w", err)
	}
	return nil
}

// MarkSettlementStatus updates a settlement row's task status — the executor's
// dispatched → done/failed lifecycle. It is a no-op when the row does not exist
// (the caller is expected to have inserted a dispatched row first).
func (s *store) MarkSettlementStatus(ctx context.Context, scanID, vulnType, rangeStr, subagentID, status string) error {
	_, err := s.exec.ExecContext(ctx,
		`UPDATE settlement_stats SET status = ? WHERE scan_id = ? AND vuln_type = ? AND range_str = ? AND subagent_id = ?`,
		status, scanID, vulnType, rangeStr, subagentID)
	if err != nil {
		return fmt.Errorf("db: mark settlement status: %w", err)
	}
	return nil
}

// IncrementSettlementRetry bumps a settlement row's retry_count by one. It is
// the retry state machine the deterministic executor uses (retry_count < 3 +
// exponential backoff); the retry budget itself is enforced by the caller.
func (s *store) IncrementSettlementRetry(ctx context.Context, scanID, vulnType, rangeStr, subagentID string) error {
	_, err := s.exec.ExecContext(ctx,
		`UPDATE settlement_stats SET retry_count = retry_count + 1, status = 'dispatched' WHERE scan_id = ? AND vuln_type = ? AND range_str = ? AND subagent_id = ?`,
		scanID, vulnType, rangeStr, subagentID)
	if err != nil {
		return fmt.Errorf("db: increment settlement retry: %w", err)
	}
	return nil
}

func (s *store) ListSettlementStatsByScan(ctx context.Context, scanID string) ([]*SettlementStat, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, scan_id, vuln_type, range_str, subagent_id, written, dismissed, evidence_opens, source_reads, repo_greps, needs_context, status, retry_count, wall_ms, created_at
		 FROM settlement_stats WHERE scan_id = ? ORDER BY vuln_type, range_str, subagent_id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list settlement stats by scan: %w", err)
	}
	defer rows.Close()
	return scanSettlementStats(rows)
}

func (s *store) ListSettlementStatsByType(ctx context.Context, vulnType string, limit int) ([]*SettlementStat, error) {
	query := `SELECT id, scan_id, vuln_type, range_str, subagent_id, written, dismissed, evidence_opens, source_reads, repo_greps, needs_context, status, retry_count, wall_ms, created_at
		 FROM settlement_stats WHERE vuln_type = ? ORDER BY created_at DESC, id DESC`
	args := []interface{}{vulnType}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("db: list settlement stats by type: %w", err)
	}
	defer rows.Close()
	return scanSettlementStats(rows)
}

func scanSettlementStats(rows *sql.Rows) ([]*SettlementStat, error) {
	var out []*SettlementStat
	for rows.Next() {
		st := &SettlementStat{}
		var wallMS sql.NullInt64
		if err := rows.Scan(&st.ID, &st.ScanID, &st.VulnType, &st.RangeStr, &st.SubagentID,
			&st.Written, &st.Dismissed, &st.EvidenceOpens, &st.SourceReads, &st.RepoGreps,
			&st.NeedsContext, &st.Status, &st.RetryCount, &wallMS, &st.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan settlement stat: %w", err)
		}
		st.WallMS = wallMS.Int64
		out = append(out, st)
	}
	return out, rows.Err()
}
