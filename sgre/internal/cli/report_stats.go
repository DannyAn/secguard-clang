package cli

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// runReportStats handles `report --stats`.
//
// --stats is the READ-ONLY per-type verdict census: confirmed / auto_confirmed
// / dismissed / remaining in one query, with NO findings/ + SARIF + xlsx
// re-render (P1-9). The orchestrator reads this instead of a second --audit.
func runReportStats(ctx context.Context, store db.Store, remaining []string) int {
	scanID := parseStringFlag(remaining, "scan-id")
	var err error
	if scanID == "" {
		scanID, err = store.GetLatestScanID(ctx)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", err))
			return 1
		}
	}
	if scanID == "" {
		WriteErrorJSON("no scan stats found; run 'secguard scan' first")
		return 1
	}
	stats, err := store.ListScanStats(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list scan stats: %v", err))
		return 1
	}
	verdictRows, err := store.DB().QueryContext(ctx,
		`SELECT vuln_type, status, COALESCE(review_status, ''), COUNT(*) FROM findings WHERE scan_id = ? GROUP BY vuln_type, status, review_status`,
		scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count verdicts by type: %v", err))
		return 1
	}
	dismissedByType, err := store.CountCandidateVerdictsByType(ctx, scanID)
	if err != nil {
		dismissedByType = map[string]int{}
	}
	type tally struct{ confirmed, auto int }
	byType := map[string]*tally{}
	for verdictRows.Next() {
		var vt, status, reviewStatus string
		var n int
		if err := verdictRows.Scan(&vt, &status, &reviewStatus, &n); err != nil {
			verdictRows.Close()
			WriteErrorJSON(fmt.Sprintf("failed to scan verdict tally: %v", err))
			return 1
		}
		if vt == "" {
			continue
		}
		if byType[vt] == nil {
			byType[vt] = &tally{}
		}
		// Mirror Finding.FinalStatus(): a review dismissal drops the row
		// from the confirmed set; an inconclusive review keeps first-pass.
		if reviewStatus == "dismissed" || reviewStatus == "suspected-kept" || reviewStatus == "false_positive" {
			continue
		}
		if status == db.StatusAutoConfirmed {
			byType[vt].auto += n
		} else if status == "confirmed" || reviewStatus == "confirmed" || reviewStatus == "ai_confirmed" {
			byType[vt].confirmed += n
		}
	}
	verdictRows.Close()
	rows := make([]map[string]interface{}, 0, len(stats))
	for _, st := range stats {
		t := byType[st.VulnType]
		confirmed, auto := 0, 0
		if t != nil {
			confirmed, auto = t.confirmed, t.auto
		}
		dismissed := dismissedByType[st.VulnType]
		// final_count counts needs-review candidates only (auto-confirmed
		// rows were never part of it) — subtracting auto here double-counted
		// the machine verdicts and could pin remaining at 0 prematurely.
		remaining := st.FinalCount - confirmed - dismissed
		if remaining < 0 {
			remaining = 0
		}
		rows = append(rows, map[string]interface{}{
			"vuln_type":       st.VulnType,
			"cwe":             planner.CWEForType(st.VulnType),
			"candidate_count": st.FinalCount,
			"confirmed":       confirmed,
			"auto_confirmed":  auto,
			"dismissed":       dismissed,
			"remaining":       remaining,
		})
	}
	_ = WriteJSON(map[string]interface{}{"scan_id": scanID, "types": rows})
	return 0
}
