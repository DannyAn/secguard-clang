package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) UpsertScanRun(ctx context.Context, r *ScanRun) error {
	if r.CreatedAt == 0 {
		r.CreatedAt = now()
	}
	if r.CompletionState == "" {
		r.CompletionState = "running"
	}
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO scan_runs (scan_id, source_revision, duration_ms, ai_duration_ms, index_ms, graph_ms, detectors_ms, plan_ms, report_ms, files_indexed, functions_indexed, seed_count, final_count, report_bytes, evidence_bytes, created_at, completion_state)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id) DO UPDATE SET
		   source_revision=excluded.source_revision,
		   duration_ms=excluded.duration_ms, ai_duration_ms=excluded.ai_duration_ms, index_ms=excluded.index_ms, graph_ms=excluded.graph_ms,
		   detectors_ms=excluded.detectors_ms, plan_ms=excluded.plan_ms, report_ms=excluded.report_ms,
		   files_indexed=excluded.files_indexed, functions_indexed=excluded.functions_indexed,
		   seed_count=excluded.seed_count, final_count=excluded.final_count, report_bytes=excluded.report_bytes,
		   evidence_bytes=excluded.evidence_bytes, created_at=excluded.created_at, completion_state=excluded.completion_state`,
		r.ScanID, r.SourceRevision, r.DurationMs, r.AIDurationMs, r.IndexMs, r.GraphMs, r.DetectorsMs, r.PlanMs, r.ReportMs,
		r.FilesIndexed, r.FunctionsIndexed, r.SeedCount, r.FinalCount, r.ReportBytes, r.EvidenceBytes, r.CreatedAt, r.CompletionState)
	if err != nil {
		return fmt.Errorf("db: upsert scan_run: %w", err)
	}
	return nil
}

// BeginScanRun inserts the scan's lifecycle row before the pipeline starts.
// It is a no-op row on a new scan and resets a re-scan of the same scan_id to
// running; the final UpsertScanRun fills in the metrics and the completion
// state is committed only at the end of the scan.
func (s *store) BeginScanRun(ctx context.Context, scanID string) error {
	if scanID == "" {
		return fmt.Errorf("db: begin scan_run: empty scan_id")
	}
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO scan_runs (scan_id, source_revision, duration_ms, ai_duration_ms, index_ms, graph_ms, detectors_ms, plan_ms, report_ms, files_indexed, functions_indexed, seed_count, final_count, report_bytes, evidence_bytes, created_at, completion_state)
		 VALUES (?, '', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?, 'running')
		 ON CONFLICT(scan_id) DO UPDATE SET
		   created_at=excluded.created_at,
		   completion_state='running'`,
		scanID, now())
	if err != nil {
		return fmt.Errorf("db: begin scan_run: %w", err)
	}
	return nil
}

// SetScanRunAIDuration records the AI-classification wall-clock for a scan. It is
// written by `report --audit --ai-duration-ms <ms>` at the end of the AI stage, so
// the two-phase pipeline-vs-AI timing is queryable across scans. It is a targeted
// UPDATE (not an upsert) so it never clobbers the pipeline timings the scan wrote.
func (s *store) SetScanRunAIDuration(ctx context.Context, scanID string, ms int64, source string) error {
	res, err := s.exec.ExecContext(ctx, `UPDATE scan_runs SET ai_duration_ms = ?, ai_duration_source = ? WHERE scan_id = ?`, ms, source, scanID)
	if err != nil {
		return fmt.Errorf("db: set scan_run ai_duration_ms: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("db: set scan_run ai_duration_ms: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("db: set scan_run ai_duration_ms: no scan_run for scan_id %q", scanID)
	}
	return nil
}

func (s *store) GetScanRun(ctx context.Context, scanID string) (*ScanRun, error) {
	r := &ScanRun{}
	var aiSource sql.NullString
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, scan_id, source_revision, duration_ms, ai_duration_ms, ai_duration_source, index_ms, graph_ms, detectors_ms, plan_ms, report_ms, files_indexed, functions_indexed, seed_count, final_count, report_bytes, evidence_bytes, created_at, COALESCE(completion_state,'complete')
		 FROM scan_runs WHERE scan_id = ?`, scanID).
		Scan(&r.ID, &r.ScanID, &r.SourceRevision, &r.DurationMs, &r.AIDurationMs, &aiSource, &r.IndexMs, &r.GraphMs, &r.DetectorsMs, &r.PlanMs, &r.ReportMs,
			&r.FilesIndexed, &r.FunctionsIndexed, &r.SeedCount, &r.FinalCount, &r.ReportBytes, &r.EvidenceBytes, &r.CreatedAt, &r.CompletionState)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get scan_run: %w", err)
	}
	r.AIDurationSource = aiSource.String
	return r, nil
}

func (s *store) ListScanRuns(ctx context.Context, limit int) ([]*ScanRun, error) {
	query := `SELECT id, scan_id, source_revision, duration_ms, ai_duration_ms, ai_duration_source, index_ms, graph_ms, detectors_ms, plan_ms, report_ms, files_indexed, functions_indexed, seed_count, final_count, report_bytes, evidence_bytes, created_at, COALESCE(completion_state,'complete')
		 FROM scan_runs ORDER BY created_at DESC, id DESC`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.exec.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("db: list scan_runs: %w", err)
	}
	defer rows.Close()
	var runs []*ScanRun
	for rows.Next() {
		r := &ScanRun{}
		var aiSource sql.NullString
		if err := rows.Scan(&r.ID, &r.ScanID, &r.SourceRevision, &r.DurationMs, &r.AIDurationMs, &aiSource, &r.IndexMs, &r.GraphMs, &r.DetectorsMs, &r.PlanMs, &r.ReportMs,
			&r.FilesIndexed, &r.FunctionsIndexed, &r.SeedCount, &r.FinalCount, &r.ReportBytes, &r.EvidenceBytes, &r.CreatedAt, &r.CompletionState); err != nil {
			return nil, fmt.Errorf("db: scan scan_run: %w", err)
		}
		r.AIDurationSource = aiSource.String
		runs = append(runs, r)
	}
	return runs, rows.Err()
}
func (s *store) SetScanRunCompletionState(ctx context.Context, scanID, state string) error {
	_, err := s.exec.ExecContext(ctx, `UPDATE scan_runs SET completion_state = ? WHERE scan_id = ?`, state, scanID)
	if err != nil {
		return fmt.Errorf("db: set completion_state: %w", err)
	}
	return nil
}

// MarkStaleRunningAsFailed flips leftover 'running' rows to 'failed', excluding
// the scan that is starting now. Without the exclusion a concurrent scan (or a
// re-scan of the same id) would clobber another live run's lifecycle row.
func (s *store) MarkStaleRunningAsFailed(ctx context.Context, excludeScanID string) (int, error) {
	res, err := s.exec.ExecContext(ctx,
		`UPDATE scan_runs SET completion_state = 'failed'
		 WHERE completion_state = 'running' AND scan_id <> ?`, excludeScanID)
	if err != nil {
		return 0, fmt.Errorf("db: mark stale running as failed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("db: mark stale running as failed: rows: %w", err)
	}
	return int(n), nil
}

// StaleRunningScanIDs returns the scan IDs currently in 'running' state,
// excluding the scan that is starting now, in creation order. Callers use it to
// mark the corresponding scan directories before MarkStaleRunningAsFailed flips
// the rows (an OOM-killed process never runs its own failure finalizer).
func (s *store) StaleRunningScanIDs(ctx context.Context, excludeScanID string) ([]string, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT scan_id FROM scan_runs WHERE completion_state = 'running' AND scan_id <> ? ORDER BY created_at`, excludeScanID)
	if err != nil {
		return nil, fmt.Errorf("db: list stale running scan ids: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("db: scan stale running id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *store) InsertIncompleteTask(ctx context.Context, task *ScanIncompleteTask) error {
	if task.CreatedAt == 0 {
		task.CreatedAt = now()
	}
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO scan_incomplete_tasks (scan_id, phase, function_id, file_path, scale, reason, detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		task.ScanID, task.Phase, task.FunctionID, task.FilePath, task.Scale, task.Reason, task.Detail, task.CreatedAt)
	if err != nil {
		return fmt.Errorf("db: insert incomplete task: %w", err)
	}
	return nil
}

func (s *store) ListIncompleteTasks(ctx context.Context, scanID string) ([]*ScanIncompleteTask, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, scan_id, phase, function_id, file_path, scale, reason, detail, created_at
		 FROM scan_incomplete_tasks WHERE scan_id = ? ORDER BY created_at`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list incomplete tasks: %w", err)
	}
	defer rows.Close()
	var tasks []*ScanIncompleteTask
	for rows.Next() {
		t := &ScanIncompleteTask{}
		if err := rows.Scan(&t.ID, &t.ScanID, &t.Phase, &t.FunctionID, &t.FilePath, &t.Scale, &t.Reason, &t.Detail, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan incomplete task: %w", err)
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}
