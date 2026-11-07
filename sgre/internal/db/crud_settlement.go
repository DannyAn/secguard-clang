package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// GetSettlementStat returns the row for one (scan, type, range), or nil when the
// batch was never claimed or settled.
func (s *store) GetSettlementStat(ctx context.Context, scanID, vulnType, rangeStr string) (*SettlementStat, error) {
	st := &SettlementStat{}
	var wallMS, queueMS, workMS, finishedAt sql.NullInt64
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, scan_id, vuln_type, range_str, subagent_id, written, dismissed, evidence_opens, source_reads, repo_greps, needs_context, status, retry_count, wall_ms, queue_ms, work_ms, finished_at, created_at
		 FROM settlement_stats WHERE scan_id = ? AND vuln_type = ? AND range_str = ?`,
		scanID, vulnType, rangeStr).Scan(&st.ID, &st.ScanID, &st.VulnType, &st.RangeStr, &st.SubagentID,
		&st.Written, &st.Dismissed, &st.EvidenceOpens, &st.SourceReads, &st.RepoGreps,
		&st.NeedsContext, &st.Status, &st.RetryCount, &wallMS, &queueMS, &workMS, &finishedAt, &st.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get settlement stat: %w", err)
	}
	st.WallMS = wallMS.Int64
	st.QueueMS = queueMS.Int64
	st.WorkMS = workMS.Int64
	st.FinishedAt = finishedAt.Int64
	return st, nil
}

// ClaimSettlementRange atomically reserves (scan_id, vuln_type, range_str) for a
// worker before dispatch — the pre-dispatch placeholder that makes two
// orchestrators racing on the same type+range converge on one worker instead of
// running the same batch twice. The decision is ONE upsert statement (SQLite
// executes it atomically): insert when free; take over only when the previous
// claim is stale (created_at < staleBefore, seconds), failed, or reclaim is true
// (a deliberate needs_context re-review). A fresh 'dispatched' claim or a 'done'
// row loses, and the result carries the current holder so the caller can skip the
// batch with a reason.
func (s *store) ClaimSettlementRange(ctx context.Context, scanID, vulnType, rangeStr, holder string, staleBefore int64, reclaim bool) (*SettlementClaim, error) {
	claim := &SettlementClaim{ScanID: scanID, VulnType: vulnType, Range: rangeStr}
	prior, err := s.GetSettlementStat(ctx, scanID, vulnType, rangeStr)
	if err != nil {
		return nil, err
	}
	reclaimFlag := 0
	if reclaim {
		reclaimFlag = 1
	}
	nowSec := now()
	var (
		gotID     int64
		gotHolder string
		gotRetry  int
	)
	err = s.exec.QueryRowContext(ctx,
		`INSERT INTO settlement_stats (scan_id, vuln_type, range_str, subagent_id, status, retry_count, created_at)
		 VALUES (?, ?, ?, ?, 'dispatched', 0, ?)
		 ON CONFLICT(scan_id, vuln_type, range_str) DO UPDATE SET
		   subagent_id = excluded.subagent_id,
		   status = 'dispatched',
		   retry_count = settlement_stats.retry_count + 1,
		   created_at = excluded.created_at
		 WHERE ? = 1
		    OR settlement_stats.status = 'failed'
		    OR (settlement_stats.status = 'dispatched' AND settlement_stats.created_at < ?)
		 RETURNING id, subagent_id, retry_count`,
		scanID, vulnType, rangeStr, holder, nowSec, reclaimFlag, staleBefore).
		Scan(&gotID, &gotHolder, &gotRetry)
	if errors.Is(err, sql.ErrNoRows) {
		held, herr := s.GetSettlementStat(ctx, scanID, vulnType, rangeStr)
		if herr != nil {
			return nil, herr
		}
		if held == nil {
			return nil, fmt.Errorf("db: claim settlement range: row vanished for %s/%s/%s", scanID, vulnType, rangeStr)
		}
		claim.Claimed = false
		claim.Reason = "held"
		if held.Status == "done" {
			claim.Reason = "done"
		}
		claim.Holder = held.SubagentID
		claim.Status = held.Status
		claim.RetryCount = held.RetryCount
		if held.CreatedAt > 0 && nowSec > held.CreatedAt {
			claim.AgeMS = (nowSec - held.CreatedAt) * 1000
		}
		return claim, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: claim settlement range: %w", err)
	}
	claim.Claimed = true
	claim.Holder = holder
	claim.Status = "dispatched"
	claim.RetryCount = gotRetry
	switch {
	case reclaim:
		claim.Reason = "reclaim"
	case prior == nil:
		claim.Reason = "new"
	case prior.Status == "failed":
		claim.Reason = "retry"
	default:
		claim.Reason = "stale"
	}
	return claim, nil
}

func (s *store) UpsertSettlementStat(ctx context.Context, st *SettlementStat) error {
	if st.CreatedAt == 0 {
		st.CreatedAt = now()
	}
	if st.Status == "" {
		st.Status = "done"
	}
	var wallMS, queueMS, workMS, finishedAt interface{}
	if st.WallMS > 0 {
		wallMS = st.WallMS
	}
	if st.QueueMS > 0 {
		queueMS = st.QueueMS
	}
	if st.WorkMS > 0 {
		workMS = st.WorkMS
	}
	if st.FinishedAt > 0 {
		finishedAt = st.FinishedAt
	}
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO settlement_stats (scan_id, vuln_type, range_str, subagent_id, written, dismissed, evidence_opens, source_reads, repo_greps, needs_context, status, retry_count, wall_ms, queue_ms, work_ms, finished_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id, vuln_type, range_str) DO UPDATE SET
		   subagent_id = excluded.subagent_id,
		   written = excluded.written,
		   dismissed = excluded.dismissed,
		   evidence_opens = excluded.evidence_opens,
		   source_reads = excluded.source_reads,
		   repo_greps = excluded.repo_greps,
		   needs_context = excluded.needs_context,
		   status = excluded.status,
		   retry_count = excluded.retry_count,
		   wall_ms = excluded.wall_ms,
		   queue_ms = excluded.queue_ms,
		   work_ms = excluded.work_ms,
		   finished_at = COALESCE(excluded.finished_at, settlement_stats.finished_at),
		   created_at = excluded.created_at`,
		st.ScanID, st.VulnType, st.RangeStr, st.SubagentID,
		st.Written, st.Dismissed, st.EvidenceOpens, st.SourceReads, st.RepoGreps, st.NeedsContext,
		st.Status, st.RetryCount, wallMS, queueMS, workMS, finishedAt, st.CreatedAt)
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

// SettleDispatchedClaims closes every leftover pre-dispatch claim placeholder
// for one (scan, type) by marking it 'done'. It is the complete-type counterpart
// to ClaimSettlementRange: once the orchestrator declares a type complete, a
// lingering 'dispatched' row must not keep reading as an in-flight batch for the
// rest of claim_ttl (a re-plan would treat the type as held and skip it, and a
// fresh claim would lose to a zombie holder). Rows that already carry a settled
// report are untouched — those are already 'done'. Returns the count closed.
func (s *store) SettleDispatchedClaims(ctx context.Context, scanID, vulnType string) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`UPDATE settlement_stats SET status = 'done'
		 WHERE scan_id = ? AND vuln_type = ? AND status = 'dispatched'`,
		scanID, vulnType)
	if err != nil {
		return 0, fmt.Errorf("db: settle dispatched claims: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("db: settle dispatched claims: rows affected: %w", err)
	}
	return n, nil
}

func (s *store) ListSettlementStatsByScan(ctx context.Context, scanID string) ([]*SettlementStat, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, scan_id, vuln_type, range_str, subagent_id, written, dismissed, evidence_opens, source_reads, repo_greps, needs_context, status, retry_count, wall_ms, queue_ms, work_ms, finished_at, created_at
		 FROM settlement_stats WHERE scan_id = ? ORDER BY vuln_type, range_str, subagent_id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list settlement stats by scan: %w", err)
	}
	defer rows.Close()
	return scanSettlementStats(rows)
}

func (s *store) ListSettlementStatsByType(ctx context.Context, vulnType string, limit int) ([]*SettlementStat, error) {
	query := `SELECT id, scan_id, vuln_type, range_str, subagent_id, written, dismissed, evidence_opens, source_reads, repo_greps, needs_context, status, retry_count, wall_ms, queue_ms, work_ms, finished_at, created_at
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
		var wallMS, queueMS, workMS, finishedAt sql.NullInt64
		if err := rows.Scan(&st.ID, &st.ScanID, &st.VulnType, &st.RangeStr, &st.SubagentID,
			&st.Written, &st.Dismissed, &st.EvidenceOpens, &st.SourceReads, &st.RepoGreps,
			&st.NeedsContext, &st.Status, &st.RetryCount, &wallMS, &queueMS, &workMS, &finishedAt, &st.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan settlement stat: %w", err)
		}
		st.WallMS = wallMS.Int64
		st.QueueMS = queueMS.Int64
		st.WorkMS = workMS.Int64
		st.FinishedAt = finishedAt.Int64
		out = append(out, st)
	}
	return out, rows.Err()
}
