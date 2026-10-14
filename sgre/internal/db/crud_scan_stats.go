package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func (s *store) InsertScanStat(ctx context.Context, stat *ScanStat) (int64, error) {
	if stat.CreatedAt == 0 {
		stat.CreatedAt = now()
	}
	return withBusyRetryID(ctx, 3, func() (int64, error) {
		res, err := s.exec.ExecContext(ctx,
			`INSERT INTO scan_stats (scan_id, vuln_type, seed_count, final_count, filter_chain, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(scan_id, vuln_type) DO UPDATE SET
			   seed_count = excluded.seed_count,
			   final_count = excluded.final_count,
			   filter_chain = excluded.filter_chain,
			   ai_stage_status = 'pending',
			   created_at = excluded.created_at`,
			stat.ScanID, stat.VulnType, stat.SeedCount, stat.FinalCount, stat.FilterChain, stat.CreatedAt)
		if err != nil {
			return 0, fmt.Errorf("db: insert scan_stat: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("db: insert scan_stat: last insert id: %w", err)
		}
		return id, nil
	})
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
// WrittenCount is the live COUNT over findings for that type's CWEs. cwesForType
// maps a vuln_type name to the full set of CWE rule_ids its findings can carry
// (planner.CWEsForType at the cli layer) — it is injected rather than imported
// so the db package never depends on planner. A type that maps to several CWEs
// (injection → CWE-78/89/88/91/93/117) has its written findings counted across
// every one of them, not just the canonical CWE. Types present in
// planner.AllVulnTypes() but absent from scan_stats (the scan never reached
// them) are NOT included here; the cli layer appends them as
// terminal_state="unknown" so the orchestrator sees the full picture.
func (s *store) ListPerTypeStatus(ctx context.Context, scanID string, cwesForType func(string) []string) ([]*PerTypeStatus, error) {
	stats, err := s.ListScanStats(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("db: list per-type status: %w", err)
	}

	// countByRule tallies findings per rule_id (CWE) under an extra WHERE
	// fragment. written_count uses status='confirmed' (AI verdicts only, so a
	// machine auto-confirmed chunk never inflates the resume comparison);
	// auto_confirmed / unreviewed_auto_confirmed expose the machine tier and its
	// re-review progress so the orchestrator can see, in ONE status call, whether
	// a 0-candidate type still has machine findings awaiting re-review.
	countByRule := func(whereFragment string) (map[string]int, error) {
		counts := make(map[string]int)
		rows, err := s.exec.QueryContext(ctx,
			`SELECT rule_id, COUNT(*) FROM findings WHERE scan_id = ? `+whereFragment+` GROUP BY rule_id`, scanID)
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
			// Normalize the stored rule_id so a hand-written lowercase finding
			// still matches the registry-derived uppercase CWE set.
			counts[strings.ToUpper(strings.TrimSpace(cwe))] += cnt
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("db: list per-type status: rows: %w", err)
		}
		return counts, nil
	}

	cweCounts, err := countByRule(`AND status = 'confirmed'`)
	if err != nil {
		return nil, err
	}
	autoCweCounts, err := countByRule(`AND status = 'auto-confirmed'`)
	if err != nil {
		return nil, err
	}
	unreviewedCweCounts, err := countByRule(`AND status = 'auto-confirmed' AND (review_status IS NULL OR review_status = '')`)
	if err != nil {
		return nil, err
	}

	result := make([]*PerTypeStatus, 0, len(stats))
	for _, st := range stats {
		cwe := ""
		written := 0
		autoConfirmed := 0
		unreviewed := 0
		if cwesForType != nil {
			cwes := cwesForType(st.VulnType)
			for _, id := range cwes {
				written += cweCounts[id]
				autoConfirmed += autoCweCounts[id]
				unreviewed += unreviewedCweCounts[id]
			}
			if len(cwes) > 0 {
				cwe = cwes[0]
			}
		}
		result = append(result, &PerTypeStatus{
			VulnType:                st.VulnType,
			CWE:                     cwe,
			CandidateCount:          st.FinalCount,
			WrittenCount:            written,
			AutoConfirmed:           autoConfirmed,
			UnreviewedAutoConfirmed: unreviewed,
			TerminalState:           inferTerminalStateByAIStageStatus(st.AIStageStatus, st.FinalCount, written),
			AIStageStatus:           st.AIStageStatus,
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
