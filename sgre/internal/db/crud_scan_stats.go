package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) InsertScanStat(ctx context.Context, stat *ScanStat) (int64, error) {
	if stat.CreatedAt == 0 {
		stat.CreatedAt = now()
	}
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO scan_stats (scan_id, vuln_type, seed_count, final_count, filter_chain, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		stat.ScanID, stat.VulnType, stat.SeedCount, stat.FinalCount, stat.FilterChain, stat.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("db: insert scan_stat: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert scan_stat: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) ListScanStats(ctx context.Context, scanID string) ([]*ScanStat, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, scan_id, vuln_type, seed_count, final_count, filter_chain, created_at FROM scan_stats WHERE scan_id = ? ORDER BY vuln_type`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list scan_stats: %w", err)
	}
	defer rows.Close()
	var stats []*ScanStat
	for rows.Next() {
		st := &ScanStat{}
		if err := rows.Scan(&st.ID, &st.ScanID, &st.VulnType, &st.SeedCount, &st.FinalCount, &st.FilterChain, &st.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan scan_stat: %w", err)
		}
		stats = append(stats, st)
	}
	return stats, rows.Err()
}

func (s *store) GetLatestScanID(ctx context.Context) (string, error) {
	var scanID string
	err := s.exec.QueryRowContext(ctx, `SELECT scan_id FROM scan_stats ORDER BY created_at DESC LIMIT 1`).Scan(&scanID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("db: get latest scan_id: %w", err)
	}
	return scanID, nil
}

func (s *store) CountFindingsByScanAndStatus(ctx context.Context, scanID, status string) (int, error) {
	var count int
	err := s.exec.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE scan_id = ? AND status = ?`, scanID, status).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("db: count findings by scan and status: %w", err)
	}
	return count, nil
}

func (s *store) ListFindingsByScanID(ctx context.Context, scanID string) ([]*Finding, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, properties, summary, reasoning, fix_strategy, exception_check, review_status, review_reasoning, scan_id, created_at FROM findings WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list findings by scan_id: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}
