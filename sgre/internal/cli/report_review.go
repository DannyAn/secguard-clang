package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// runReportCompleteType handles `report --complete-type`.
func runReportCompleteType(ctx context.Context, store db.Store, remaining []string) int {
	vulnType := parseStringFlag(remaining, "complete-type")
	scanID := parseStringFlag(remaining, "scan-id")
	if vulnType == "" {
		WriteErrorJSON("--complete-type requires a vulnerability type argument")
		return 1
	}
	if scanID == "" {
		WriteErrorJSON("--complete-type requires --scan-id")
		return 1
	}
	stats, err := store.ListScanStats(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to validate scan_id: %v", err))
		return 1
	}
	if len(stats) == 0 {
		WriteErrorJSON(fmt.Sprintf("unknown scan_id %q: no scan_stats found for this id", scanID))
		return 1
	}
	known := false
	for _, t := range planner.AllVulnTypes() {
		if t == vulnType {
			known = true
			break
		}
	}
	if !known {
		WriteErrorJSON(fmt.Sprintf("unsupported vuln_type %q: not a registered vulnerability type", vulnType))
		return 1
	}
	found := false
	for _, st := range stats {
		if st.VulnType == vulnType {
			found = true
			break
		}
	}
	if !found {
		WriteErrorJSON(fmt.Sprintf("no scan_stats for (scan_id=%q, vuln_type=%q)", scanID, vulnType))
		return 1
	}
	// Completion is PROVEN by the verdict ledger, NOT by settlement files:
	// a type is complete iff every candidate has a terminal verdict
	// (unclassified == 0). This is the SAME identity the audit's
	// unclassified metric uses, and it works on hosts whose subagents write
	// verdicts via the MCP tool and never produce settlement files (the F13
	// claim ↔ complete-type deadlock). An unfinished type (a live worker,
	// a never-started range, needs_context residue) has unclassified > 0
	// and is refused; a fully classified type settles its own claims below.
	candidateCount := 0
	for _, st := range stats {
		if st.VulnType == vulnType {
			candidateCount = st.FinalCount
		}
	}
	writtenCount := 0
	findings, err := store.ListFindingsByScanID(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to load findings for verdict coverage: %v", err))
		return 1
	}
	for _, f := range findings {
		if f.VulnType == vulnType && f.Status == "confirmed" {
			writtenCount++
		}
	}
	dismissedByType, err := store.CountCandidateVerdictsByType(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count dismissed verdicts: %v", err))
		return 1
	}
	dismissedCount := dismissedByType[vulnType]
	unclassified := candidateCount - writtenCount - dismissedCount
	if unclassified > 0 {
		uncovered := []string{}
		if settlements, serr := store.ListSettlementStatsByScan(ctx, scanID); serr == nil {
			var typeRows []*db.SettlementStat
			for _, st := range settlements {
				if st.VulnType == vulnType {
					typeRows = append(typeRows, st)
				}
			}
			cov := deriveTypeCoverage(typeRows, candidateCount, time.Now().UnixMilli())
			uncovered = cov.Uncovered
		}
		_ = WriteJSON(map[string]interface{}{
			"status":           "incomplete",
			"scan_id":          scanID,
			"vuln_type":        vulnType,
			"candidate_count":  candidateCount,
			"written_count":    writtenCount,
			"dismissed_count":  dismissedCount,
			"unclassified":     unclassified,
			"uncovered_ranges": uncovered,
			"error":            "type is not fully classified: every candidate needs a terminal verdict (confirmed or dismissed) before --complete-type; re-dispatch the uncovered ranges",
			"ai_stage_status":  "in-progress",
		})
		return 1
	}
	if err := store.MarkAIStageDone(ctx, scanID, vulnType); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to mark ai_stage_done: %v", err))
		return 1
	}
	// The ledger proves the work is done, so the type's own dispatched
	// claims are settled (NOT a blind pseudo-settlement: unclassified == 0
	// means every range's candidates already carry a verdict, including any
	// sibling range's). A range that never ran keeps unclassified > 0 above.
	if err := store.WithImmediateTx(ctx, func(tx db.Store) error {
		rows, err := tx.ListSettlementStatsByScan(ctx, scanID)
		if err != nil {
			return err
		}
		for _, st := range rows {
			if st.VulnType == vulnType && st.Status == "dispatched" {
				if err := tx.MarkSettlementStatus(ctx, st.ScanID, st.VulnType, st.RangeStr, st.SubagentID, "done"); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to settle dispatched claims: %v", err))
		return 1
	}
	_ = WriteJSON(map[string]interface{}{
		"scan_id":         scanID,
		"vuln_type":       vulnType,
		"ai_stage_status": "done",
		"status":          "ok",
	})
	return 0
}

// runReportReview handles `report --review` (single-finding review).
func runReportReview(ctx context.Context, store db.Store, remaining []string) int {
	findingID := int64(parseIntFlag(remaining, "id"))
	if findingID == 0 {
		WriteErrorJSON("--review requires --id=<finding_id>")
		return 1
	}
	reviewStatus := parseStringFlag(remaining, "review-status")
	reviewReasoning := parseStringFlag(remaining, "review-reasoning")
	switch reviewStatus {
	case "confirmed", "dismissed", "needs_more_evidence":
	default:
		WriteErrorJSON(fmt.Sprintf("invalid --review-status %q (expected confirmed|dismissed|needs_more_evidence)", reviewStatus))
		return 1
	}

	f, err := store.GetFindingByID(ctx, findingID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to load finding: %v", err))
		return 1
	}

	if err := store.UpdateFindingReview(ctx, findingID, reviewStatus, reviewReasoning); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to update review: %v", err))
		return 1
	}

	finalStatus := reviewStatus
	// Re-send the structured content the first pass persisted, so the A5
	// review updates the verdict without wiping Summary/Reasoning/Fix
	// Strategy — and so a dismissal removes the file from findings/ rather
	// than leaving a confirmed-looking file behind. Record the review on
	// ReviewStatus (not Status) so needs_more_evidence keeps the first-pass
	// status via EffectiveStatus (conservative: an inconclusive review never
	// drops a potential real defect).
	reviewed := *f
	reviewed.ReviewStatus = finalStatus
	oc := syncPerFindingAfterWrite(remaining, &reviewed)

	out := map[string]interface{}{
		"id":                 findingID,
		"review_status":      reviewStatus,
		"status":             "ok",
		"per_finding_path":   oc.Path,
		"per_finding_action": oc.Action,
	}
	if oc.Warning != "" {
		out["per_finding_warning"] = oc.Warning
		fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
	}
	_ = WriteJSON(out)
	return 0
}

// runReportReviewJSON handles `report --review-json` (batch review).
//
// --review-json <file> records the A5 second-round verdicts for a WHOLE batch
// of findings in ONE subprocess + ONE transaction, instead of the per-finding
// `--review` loop that spawns a subprocess and opens SQLite per
// row (the slow path that stretched a high-volume type like null-deref to
// tens of minutes). Input is a JSON array of {id, review_status,
// review_reasoning}. `-` or a missing value reads from stdin.
func runReportReviewJSON(ctx context.Context, store db.Store, remaining []string) int {
	src := parseStringFlag(remaining, "review-json")
	var data []byte
	var err error
	if src == "" || src == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to read --review-json input: %v", err))
		return 1
	}

	type reviewInput struct {
		ID              int64  `json:"id"`
		ReviewStatus    string `json:"review_status"`
		ReviewReasoning string `json:"review_reasoning"`
	}
	var inputs []reviewInput
	if err := json.Unmarshal(data, &inputs); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to parse --review-json array: %v", err))
		return 1
	}

	reviewed := make([]map[string]interface{}, 0, len(inputs))
	reviewedForSync := []reviewInput{}
	var errs []string
	// Pre-fetch the re-reviewable id set OUTSIDE the transaction: a deferred
	// WithTx built a read snapshot first and then upgraded to writes, which
	// returns SQLITE_BUSY_SNAPSHOT under concurrent writers (and the busy
	// handler does not retry that class). BEGIN IMMEDIATE takes the write
	// lock once, and the transaction body is now pure UPDATEs.
	allowed := map[int64]bool{}
	rows, qerr := store.DB().QueryContext(ctx, `SELECT id FROM findings WHERE status = 'auto-confirmed'`)
	if qerr != nil {
		WriteErrorJSON(fmt.Sprintf("failed to load auto-confirmed ids: %v", qerr))
		return 1
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			WriteErrorJSON(fmt.Sprintf("failed to scan auto-confirmed id: %v", err))
			return 1
		}
		allowed[id] = true
	}
	rows.Close()
	err = store.WithImmediateTx(ctx, func(tx db.Store) error {
		for i, in := range inputs {
			// A misspelled/omitted key decodes to the zero value, so name the
			// offending entry position and the expected keys instead of
			// reporting a bare `invalid review_status ""` — the caller
			// otherwise cannot tell a typo'd key from an invalid value.
			if in.ID == 0 {
				errs = append(errs, fmt.Sprintf("entry %d: missing required field \"id\" (expected {\"id\": <finding id>, \"review_status\": \"confirmed\"|\"dismissed\"|\"needs_more_evidence\"})", i))
				continue
			}
			switch in.ReviewStatus {
			case "confirmed", "dismissed", "needs_more_evidence":
			default:
				if in.ReviewStatus == "" {
					errs = append(errs, fmt.Sprintf("entry %d (finding %d): missing required field \"review_status\" (expected \"confirmed\", \"dismissed\", or \"needs_more_evidence\"; a misspelled key decodes as empty)", i, in.ID))
				} else {
					errs = append(errs, fmt.Sprintf("entry %d (finding %d): invalid review_status %q (expected \"confirmed\", \"dismissed\", or \"needs_more_evidence\")", i, in.ID, in.ReviewStatus))
				}
				continue
			}
			// Only machine auto-confirmed findings are re-reviewable; a verdict
			// for any other finding id must not overwrite its status (RV-04).
			if !allowed[in.ID] {
				errs = append(errs, fmt.Sprintf("finding %d — not an auto-confirmed finding; re-review only applies to auto-confirmed findings", in.ID))
				continue
			}
			if uerr := tx.UpdateFindingReview(ctx, in.ID, in.ReviewStatus, in.ReviewReasoning); uerr != nil {
				errs = append(errs, fmt.Sprintf("finding %d — %v", in.ID, uerr))
				continue
			}
			reviewed = append(reviewed, map[string]interface{}{
				"id": in.ID, "review_status": in.ReviewStatus,
			})
			reviewedForSync = append(reviewedForSync, in)
		}
		return nil
	})
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to commit review batch: %v", err))
		return 1
	}

	// Mirror the single --review path: re-fetch each reviewed finding and
	// sync its per-finding markdown so a dismissal removes the file from
	// findings/ (and a confirmation writes it) after the batch commit.
	for _, in := range reviewedForSync {
		f, gerr := store.GetFindingByID(ctx, in.ID)
		if gerr != nil {
			fmt.Fprintf(os.Stderr, "warning: re-fetch reviewed finding %d: %v\n", in.ID, gerr)
			continue
		}
		rev := *f
		rev.ReviewStatus = in.ReviewStatus
		if oc := syncPerFindingAfterWrite(remaining, &rev); oc.Warning != "" {
			fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
		}
	}

	out := map[string]interface{}{
		"status":       "ok",
		"reviewed":     reviewed,
		"review_count": len(reviewed),
	}
	if len(errs) > 0 {
		out["status"] = "partial"
		out["errors"] = errs
	}
	_ = WriteJSON(out)
	// A partial review is a failed review: exit non-zero so the orchestrator
	// cannot misread a dropped verdict as "already persisted".
	if len(errs) > 0 {
		return 1
	}
	return 0
}
