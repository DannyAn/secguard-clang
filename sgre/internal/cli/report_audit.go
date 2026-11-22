package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// runReportAudit handles `report --audit`.
func runReportAudit(ctx context.Context, store db.Store, dbPath string, remaining []string) int {
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

	// Fail an unknown scan_id before any artifact (or settlement absorption)
	// runs: a typo'd id must not mint a full set of empty, vuln_count=0
	// artifacts that read as a clean scan. The error names the closest known
	// scan id, so an orchestrator's single-character transcription error is
	// caught here instead of silently faking a completed audit.
	if verr := validateAuditScanID(ctx, store, scanID); verr != nil {
		WriteErrorJSON(verr.Error())
		return 1
	}

	// The AI-stage timing and the covered/in-flight ledger are derived from the
	// settlement reports the subagents write into .sgre/.tmp. The command
	// contract's happy path is `report --complete-type` + `report --audit`; it
	// need not (and in practice often does not) call `status --reports`.
	// Absorb the settlement files here too, so the audit self-measures the AI
	// stage and closes the pre-dispatch claims even when the orchestrator
	// skipped the explicit `status --reports` absorption step. Absorption is
	// idempotent, so a prior poll being re-run here is harmless.
	if res := listSubagentReports(dbPath, scanID); len(res.Reports) > 0 {
		if aerr := persistSettlementReports(ctx, store, res); aerr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to absorb settlement reports for audit: %v\n", aerr)
		}
	}

	// AI-stage timing is now MEASURED by the engine from the settlement
	// reports' timestamps (`status --reports` persists each batch's finish
	// time). `--ai-duration-ms` is only an override for a host that cannot
	// write settlement files; supplying it wins over the self-measurement.
	var aiTiming aiStageTiming
	if settlements, lerr := store.ListSettlementStatsByScan(ctx, scanID); lerr == nil {
		aiTiming = measureAIStageTiming(settlements)
	}
	if raw := parseStringFlag(remaining, "ai-duration-ms"); raw != "" {
		ms, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil || ms < 0 {
			WriteErrorJSON(fmt.Sprintf("invalid --ai-duration-ms %q (expected a non-negative integer of milliseconds)", raw))
			return 1
		}
		// measured = wall-clock from a nanosecond timer; estimated = a
		// seconds-resolution approximation (P2-14). The source is persisted
		// so a production A/B never compares a measured number to a guess.
		source := parseStringFlag(remaining, "ai-duration-source")
		if source == "" {
			source = "measured"
		}
		if serr := store.SetScanRunAIDuration(ctx, scanID, ms, source); serr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to record ai_duration_ms: %v", serr))
			return 1
		}
		aiTiming.TotalMS = ms
		aiTiming.Source = "override"
	} else if aiTiming.TotalMS > 0 {
		// Best-effort: a review/diff scan has no scan_runs row, and a missing
		// metrics row must not fail the audit. The timing is still rendered.
		if serr := store.SetScanRunAIDuration(ctx, scanID, aiTiming.TotalMS, "self-measured"); serr != nil {
			fmt.Fprintf(os.Stderr, "warning: could not record self-measured ai_duration_ms: %v\n", serr)
		}
	}

	stats, err := store.ListScanStats(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list scan stats: %v", err))
		return 1
	}

	// Final-artifact gate: an audit must not present an unfinished AI stage
	// as a complete verdict set. Any type with candidates whose AI stage is
	// not done blocks the terminal artifacts unless the caller explicitly
	// asks for a partial report, in which case every artifact is labelled.
	allowPartial := hasFlag(remaining, "allow-partial")
	if !allowPartial {
		var unfinished []string
		for _, st := range stats {
			if st.FinalCount > 0 && st.AIStageStatus != "done" {
				unfinished = append(unfinished, fmt.Sprintf("%s(%s, candidates=%d)", st.VulnType, st.AIStageStatus, st.FinalCount))
			}
		}
		if len(unfinished) > 0 {
			_ = WriteJSON(map[string]interface{}{
				"status":           "incomplete",
				"scan_id":          scanID,
				"unfinished_types": unfinished,
				"error":            "AI classification is not complete for these types; finish and settle them, or re-run with --allow-partial for an explicitly partial report",
			})
			return 1
		}
	}

	scanFindings, err := store.ListFindingsByScanID(ctx, scanID)
	if err != nil {
		// The audit report and result.sarif/result.xlsx are derived from these
		// findings; a read failure must not silently produce an empty report.
		WriteErrorJSON(fmt.Sprintf("failed to list findings for scan: %v", err))
		return 1
	}
	// Collapse duplicate rows that differ only by file-path spelling (the
	// absolute vs truncated double-write), and normalize paths to absolute so
	// every downstream report resolves source + embeds code context.
	scanFindings = dedupeAndNormalizeFindings(ctx, store, scanFindings)
	type vulnCounts struct {
		confirmed, suspected, autoConfirmed, reviewedOut int
	}
	countsByVuln := make(map[string]*vulnCounts)
	for _, f := range scanFindings {
		vt := f.VulnType
		if vt == "" {
			vt = planner.TypeForCWE(f.RuleID)
		}
		if vt == "" {
			continue
		}
		if countsByVuln[vt] == nil {
			countsByVuln[vt] = &vulnCounts{}
		}
		// Machine verdicts are counted apart from AI verdicts so the
		// audit-report can show both, and so the "candidates without AI
		// classification" remainder (final_count = needs-review candidates)
		// is not masked by the auto-confirmed rows.
		switch f.FinalStatus() {
		case "confirmed":
			if f.Status == db.StatusAutoConfirmed {
				countsByVuln[vt].autoConfirmed++
			} else {
				countsByVuln[vt].confirmed++
			}
		case "suspected":
			countsByVuln[vt].suspected++
		case "dismissed":
			// A machine (auto-confirmed) verdict the final review dismissed
			// is traceability the audit must not silently drop to 0 (A5):
			// count it apart so the report can say "N machine verdicts were
			// reviewed-out" instead of leaving the Auto-confirmed column at
			// 0 with no explanation.
			if f.Status == db.StatusAutoConfirmed {
				countsByVuln[vt].reviewedOut++
			}
		}
	}

	dismissedByType, err := store.CountCandidateVerdictsByType(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count dismissed verdicts: %v", err))
		return 1
	}
	audits := make([]vulnAuditEntry, 0, len(stats))
	for _, st := range stats {
		vc := countsByVuln[st.VulnType]
		if vc == nil {
			vc = &vulnCounts{}
		}
		unclassified := st.FinalCount - vc.confirmed - dismissedByType[st.VulnType]
		if unclassified < 0 {
			unclassified = 0
		}
		audits = append(audits, vulnAuditEntry{
			VulnType:        st.VulnType,
			SeedCount:       st.SeedCount,
			FinalCount:      st.FinalCount,
			Filters:         st.FilterChain,
			Confirmed:       vc.confirmed,
			Suspected:       vc.suspected,
			AutoConfirmed:   vc.autoConfirmed,
			AutoReviewedOut: vc.reviewedOut,
			AIStageStatus:   st.AIStageStatus,
			Dismissed:       dismissedByType[st.VulnType],
			Unclassified:    unclassified,
		})
	}

	outputDir := parseStringFlag(remaining, "output-dir")

	// The scan-scale + aggregate block every reader-facing artifact opens
	// with. It is built once here and shared by report.md, audit-report.md
	// and the `summary` field of this command's JSON envelope, so the three
	// can never disagree about how big the scan was or how many issues it
	// found. Verdict figures are re-derived from the findings table, never
	// from a second source.
	overview := buildScanOverview(ctx, store, scanID, stats, scanFindings, audits)
	overview.Partial = allowPartial
	// Completeness signals are computed regardless of --output-dir so a
	// `report --audit` run without an output dir still surfaces them: a
	// converged candidate with no persisted verdict is a silent false
	// negative unless the JSON the orchestrator reads says so.

	orphans, err := countFindingsWithoutScanID(ctx, store)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count findings without scan_id: %v", err))
		return 1
	}

	// Machine (auto-confirmed) verdicts were written WITHOUT AI review; the
	// re-review pass is what corrects a wrong one. A type with 0 candidates
	// gets no subagent, so its auto-confirmed findings can be audited
	// unreviewed — a real defect then reaches the final report machine-stamped
	// and an FP reaches it as a false positive. Count them so the audit
	// envelope says so instead of finalizing silently.
	unreviewed, err := unreviewedAutoConfirmedCount(ctx, store, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count unreviewed auto-confirmed findings: %v", err))
		return 1
	}

	if outputDir != "" {
		auditPath := filepath.Join(outputDir, "audit-report.md")
		if err := writeAuditReport(auditPath, scanID, audits, overview, aiTiming); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write audit report: %v", err))
			return 1
		}
		// Regenerate result.sarif from the AI's persisted findings so the
		// machine-readable report carries the post-A5 verdict + reasoning +
		// fix, not just the candidate-stage evidence. Confirmed only — the AI
		// verdict is binary, so there is no suspected stage to export.
		sarifPath := filepath.Join(outputDir, report.SarifFile)
		writeSarif := report.WriteSarifFromFindings
		if allowPartial {
			writeSarif = report.WriteSarifFromFindingsPartial
		}
		if err := writeSarif(sarifPath, "", scanFindings); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write result.sarif: %v", err))
			return 1
		}
		// Regenerate report.md from the AI's persisted findings so the
		// human-readable report shows confirmed verdicts only, not the
		// candidate-stage leads that writeReport emitted at scan time.
		reportPath := filepath.Join(outputDir, report.ReportFile)
		if err := report.WriteReportFromFindings(reportPath, "", scanFindings, overview); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write report.md: %v", err))
			return 1
		}
		// Regenerate result.xlsx from the same persisted findings: a one-way
		// export for the development team to locate, analyze, and confirm
		// every actionable finding inside a spreadsheet (dismissed excluded).
		xlsxPath := filepath.Join(outputDir, report.ResultXlsxFile)
		if err := report.WriteXlsxFromFindings(xlsxPath, "", scanFindings); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write result.xlsx: %v", err))
			return 1
		}
		// pipeline-dismissed.json is the tool's AI-dismissal ledger (P1-8):
		// the dismissed verdicts persisted in candidate_verdicts are rendered
		// here so the customer can see what the AI rejected and why. It is
		// deliberately NOT named ai-dismissed.json — that filename belongs to
		// the orchestrator's own human-review recall ledger (needs_context +
		// per-type dismissed counts), and overwriting it here would wipe the
		// entries that live only in the orchestrator's aggregation.
		if verdicts, verr := store.ListCandidateVerdicts(ctx, scanID); verr == nil {
			type dismissedRow struct {
				VulnType string `json:"vuln_type"`
				File     string `json:"file"`
				Line     int    `json:"line"`
				Function string `json:"function,omitempty"`
				Variable string `json:"variable,omitempty"`
				Reason   string `json:"reason,omitempty"`
			}
			rows := make([]dismissedRow, 0, len(verdicts))
			for _, v := range verdicts {
				rows = append(rows, dismissedRow{VulnType: v.VulnType, File: v.FilePath, Line: v.LineNumber, Function: v.FunctionName, Variable: v.Variable, Reason: v.Reason})
			}
			if data, merr := json.MarshalIndent(map[string]interface{}{"scan_id": scanID, "total_dismissed": len(rows), "dismissed": rows}, "", "  "); merr == nil {
				_ = os.WriteFile(filepath.Join(outputDir, "pipeline-dismissed.json"), append(data, '\n'), 0644)
			}
		}
		// Rebuild findings/ from the DB so the review surface holds exactly
		// the actionable verdicts: dismissed entries and never-classified
		// leftovers are swept out instead of being handed to a reviewer.
		rec, err := report.ReconcileFindings(outputDir, scanFindings)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to reconcile findings dir: %v", err))
			return 1
		}
		out := map[string]interface{}{
			"scan_id":         scanID,
			"audit_path":      auditPath,
			"sarif_path":      sarifPath,
			"report_path":     reportPath,
			"xlsx_path":       xlsxPath,
			"vuln_count":      len(audits),
			"findings_synced": rec,
			"status":          "ok",
			// The orchestrator needs the per-type verdict breakdown to build
			// its report and reconcile subagent counts. Without it here, it
			// falls back to a raw `secguard db` query over findings and
			// guesses a nonexistent column (type instead of rule_id), which
			// costs a schema-discovery round-trip.
			"audits": audits,
			// The aggregate the per-type breakdown lacks: scan scale (files /
			// functions / lines) plus the confirmed/dismissed totals and the
			// one-line headline. It is the same object
			// report.md renders, so echoing `summary` into the console can
			// never contradict the report — and the orchestrator never has to
			// add up `audits` itself (the console used to show per-type
			// counts with no total at all).
			"summary": overview.SummaryFields(),
		}
		if allowPartial {
			out["partial"] = true
		}
		// The engine-measured AI stage (total + per type) so the orchestrator
		// can report it without hand-estimating a wall clock. Omitted when the
		// scan has no settlement timing at all.
		if aiTiming.TotalMS > 0 {
			out["ai_stage"] = aiTiming
		}

		// A finding with no scan_id has no scan directory, so its verdict
		// file cannot be placed or reconciled. Surface it instead of
		// letting the review surface be quietly incomplete.
		auditNoticeFields(out, orphans, unreviewed, overview.Unclassified)
		// findings/ is a projection of the DB, so its file count must equal
		// the number of confirmed results the same invocation just wrote to
		// result.sarif. If a confirmed row could not be placed (an unmapped
		// rule_id with no known vuln_type, a write error), say so instead of
		// shipping a review surface that is silently short.
		confirmedResults := 0
		for _, f := range scanFindings {
			if f.FinalStatus() == "confirmed" {
				confirmedResults++
			}
		}
		if rec.Written != confirmedResults {
			msg := fmt.Sprintf("%s/ holds %d file(s) for %d confirmed finding(s) — the review surface does not match the DB/result.sarif", report.FindingsDir, rec.Written, confirmedResults)
			if prev, ok := out["warning"].(string); ok && prev != "" {
				msg = prev + "; " + msg
			}
			out["warning"] = msg
		}
		_ = WriteJSON(out)
	} else {
		out := map[string]interface{}{
			"scan_id": scanID,
			"audits":  audits,
			"summary": overview.SummaryFields(),
		}
		if allowPartial {
			out["partial"] = true
		}
		if aiTiming.TotalMS > 0 {
			out["ai_stage"] = aiTiming
		}
		auditNoticeFields(out, orphans, unreviewed, overview.Unclassified)
		_ = WriteJSON(out)
	}
	return 0
}
