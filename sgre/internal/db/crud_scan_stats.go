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
		`SELECT id, scan_id, vuln_type, seed_count, final_count, filter_chain, ai_stage_status, created_at FROM scan_stats WHERE scan_id = ? ORDER BY vuln_type`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list scan_stats: %w", err)
	}
	defer rows.Close()
	var stats []*ScanStat
	for rows.Next() {
		st := &ScanStat{}
		if err := rows.Scan(&st.ID, &st.ScanID, &st.VulnType, &st.SeedCount, &st.FinalCount, &st.FilterChain, &st.AIStageStatus, &st.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan scan_stat: %w", err)
		}
		stats = append(stats, st)
	}
	return stats, rows.Err()
}

func (s *store) GetLatestScanID(ctx context.Context) (string, error) {
	var scanID string
	err := s.exec.QueryRowContext(ctx, `SELECT scan_id FROM scan_stats ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&scanID)
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
		`SELECT id, rule_id, severity, confidence, evidence, status, file_path, line_number, function_name, variable, properties, summary, reasoning, fix_strategy, exception_check, review_status, review_reasoning, scan_id, fingerprint, created_at FROM findings WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list findings by scan_id: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// ListPerTypeStatus returns the per-vulnerability-type progress for a scan, the
// authoritative resume state. CandidateCount comes from scan_stats.final_count;
// WrittenCount is the live COUNT over findings for that type's CWE. cweForType
// maps a vuln_type name to its CWE rule_id (planner.CWEForType at the cli layer)
// — it is injected rather than imported so the db package never depends on
// planner. Types present in planner.AllVulnTypes() but absent from scan_stats
// (the scan never reached them) are NOT included here; the cli layer appends
// them as terminal_state="unknown" so the orchestrator sees the full picture.
func (s *store) ListPerTypeStatus(ctx context.Context, scanID string, cweForType func(string) string) ([]*PerTypeStatus, error) {
	stats, err := s.ListScanStats(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list per-type status: %w", err)
	}

	cweCounts := make(map[string]int)
	// written_count counts AI-written confirmed verdicts only. Dismissed
	// candidates are not persisted (no finding row), and auto-confirmed rows
	// are machine verdicts excluded so the resume check compares final_count
	// (the candidates the AI must classify) against the number the AI actually
	// wrote — an AI pass that never ran stays 0 even when the pipeline
	// auto-confirmed a chunk of the type.
	rows, err := s.exec.QueryContext(ctx,
		`SELECT rule_id, COUNT(*) FROM findings WHERE scan_id = ? AND status = 'confirmed' GROUP BY rule_id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list per-type status: count findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cwe string
		var cnt int
		if err := rows.Scan(&cwe, &cnt); err != nil {
			return nil, fmt.Errorf("db: list per-type status: scan: %w", err)
		}
		cweCounts[cwe] = cnt
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: list per-type status: rows: %w", err)
	}

	result := make([]*PerTypeStatus, 0, len(stats))
	for _, st := range stats {
		cwe := ""
		if cweForType != nil {
			cwe = cweForType(st.VulnType)
		}
		written := cweCounts[cwe]
		result = append(result, &PerTypeStatus{
			VulnType:       st.VulnType,
			CWE:            cwe,
			CandidateCount: st.FinalCount,
			WrittenCount:   written,
			TerminalState:  inferTerminalStateByAIStageStatus(st.AIStageStatus, st.FinalCount, written),
			AIStageStatus:  st.AIStageStatus,
		})
	}
	return result, nil
}

// inferTerminalStateByAIStageStatus classifies a type's progress from its
// ai_stage_status plus candidate/confirmed counts. The orchestrator uses this
// to decide what to resume: "done" types are skipped, "in-progress"/"pending"
// are re-dispatched, "failed" is surfaced as a type the AI stage could not
// settle. ai_stage_status is the authoritative signal — confirmed_count only
// disambiguates "pending" (AI not started) from "in-progress" (AI wrote some).
func inferTerminalStateByAIStageStatus(aiStageStatus string, finalCount, confirmedCount int) string {
	switch aiStageStatus {
	case "done":
		return "done"
	case "failed":
		return "failed"
	default:
		if finalCount == 0 {
			return "done"
		}
		if confirmedCount > 0 {
			return "in-progress"
		}
		return "pending"
	}
}

// MarkAIStageDone marks the AI classification stage done for a (scan_id,
// vuln_type) pair by setting ai_stage_status='done'. It is the single write
// entry point for the done state; 'failed' is reserved for future error
// reporting. Idempotent: re-running on an already-done row is a no-op.
func (s *store) MarkAIStageDone(ctx context.Context, scanID, vulnType string) error {
	res, err := s.exec.ExecContext(ctx,
		`UPDATE scan_stats SET ai_stage_status = 'done' WHERE scan_id = ? AND vuln_type = ?`, scanID, vulnType)
	if err != nil {
		return fmt.Errorf("db: mark ai_stage_done: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("db: mark ai_stage_done: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("db: mark ai_stage_done: no scan_stats for (scan_id=%q, vuln_type=%q)", scanID, vulnType)
	}
	return nil
}
