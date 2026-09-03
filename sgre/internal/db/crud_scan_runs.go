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
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO scan_runs (scan_id, duration_ms, index_ms, graph_ms, detectors_ms, plan_ms, report_ms, files_indexed, functions_indexed, seed_count, final_count, report_bytes, evidence_bytes, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id) DO UPDATE SET
		   duration_ms=excluded.duration_ms, index_ms=excluded.index_ms, graph_ms=excluded.graph_ms,
		   detectors_ms=excluded.detectors_ms, plan_ms=excluded.plan_ms, report_ms=excluded.report_ms,
		   files_indexed=excluded.files_indexed, functions_indexed=excluded.functions_indexed,
		   seed_count=excluded.seed_count, final_count=excluded.final_count, report_bytes=excluded.report_bytes,
		   evidence_bytes=excluded.evidence_bytes, created_at=excluded.created_at`,
		r.ScanID, r.DurationMs, r.IndexMs, r.GraphMs, r.DetectorsMs, r.PlanMs, r.ReportMs,
		r.FilesIndexed, r.FunctionsIndexed, r.SeedCount, r.FinalCount, r.ReportBytes, r.EvidenceBytes, r.CreatedAt)
	if err != nil {
		return fmt.Errorf("db: upsert scan_run: %w", err)
	}
	return nil
}

func (s *store) GetScanRun(ctx context.Context, scanID string) (*ScanRun, error) {
	r := &ScanRun{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, scan_id, duration_ms, index_ms, graph_ms, detectors_ms, plan_ms, report_ms, files_indexed, functions_indexed, seed_count, final_count, report_bytes, evidence_bytes, created_at
		 FROM scan_runs WHERE scan_id = ?`, scanID).
		Scan(&r.ID, &r.ScanID, &r.DurationMs, &r.IndexMs, &r.GraphMs, &r.DetectorsMs, &r.PlanMs, &r.ReportMs,
			&r.FilesIndexed, &r.FunctionsIndexed, &r.SeedCount, &r.FinalCount, &r.ReportBytes, &r.EvidenceBytes, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get scan_run: %w", err)
	}
	return r, nil
}

func (s *store) ListScanRuns(ctx context.Context, limit int) ([]*ScanRun, error) {
	query := `SELECT id, scan_id, duration_ms, index_ms, graph_ms, detectors_ms, plan_ms, report_ms, files_indexed, functions_indexed, seed_count, final_count, report_bytes, evidence_bytes, created_at
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
		if err := rows.Scan(&r.ID, &r.ScanID, &r.DurationMs, &r.IndexMs, &r.GraphMs, &r.DetectorsMs, &r.PlanMs, &r.ReportMs,
			&r.FilesIndexed, &r.FunctionsIndexed, &r.SeedCount, &r.FinalCount, &r.ReportBytes, &r.EvidenceBytes, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan scan_run: %w", err)
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}
