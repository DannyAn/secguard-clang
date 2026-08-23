package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

func parseStringFlag(args []string, flag string) string {
	prefix := "--" + flag + "="
	flagName := "--" + flag
	for i, a := range args {
		if strings.HasPrefix(a, prefix) {
			return a[len(prefix):]
		}
		if a == flagName && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// classifyWriteErr categorizes a finding-write error for the failed_details
// report: "write-busy" for SQLITE_BUSY/retry-exhaustion (the multi-subagent
// concurrent write storm), "write-error" for everything else. The class lands
// in the --write-json JSON output so the orchestrator can mark a type as
// missing due to contention vs a real data error.
func classifyWriteErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "busy retry exhausted") ||
		strings.Contains(s, "database is locked") ||
		strings.Contains(s, "SQLITE_BUSY") {
		return "write-busy"
	}
	return "write-error"
}

func parseFloatFlag(args []string, flag string) float64 {
	s := parseStringFlag(args, flag)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func parseIntFlag(args []string, flag string) int {
	s := parseStringFlag(args, flag)
	if s == "" {
		return 0
	}
	v, _ := strconv.Atoi(s)
	return v
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == "--"+flag {
			return true
		}
	}
	return false
}

func removeFlag(args []string, flag string) []string {
	flagName := "--" + flag
	prefix := flagName + "="
	result := []string{}
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == flagName {
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, prefix) {
			continue
		}
		result = append(result, a)
	}
	return result
}

// parseExcludeFlag extracts a comma-separated `--exclude` directory list.
// present reports whether the flag was given at all; when it is, dirs is the
// (possibly empty) parsed list and the caller overrides the default excludes.
func parseExcludeFlag(args []string) (dirs []string, present bool) {
	for i, a := range args {
		if a == "--exclude" {
			if i+1 < len(args) {
				return splitComma(args[i+1]), true
			}
			return []string{}, true
		}
		if strings.HasPrefix(a, "--exclude=") {
			return splitComma(strings.TrimPrefix(a, "--exclude=")), true
		}
	}
	return nil, false
}

func splitComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func runReportCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)

	dbPath = resolveDBPath(dbExplicit, dbPath, ".")

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	if hasFlag(remaining, "write") {
		confidence := parseFloatFlag(remaining, "confidence")
		if confidence > 1.0 {
			confidence = confidence / 100.0
		}
		// Clamp to the DB's [0,1] CHECK range so an out-of-range confidence
		// (e.g. 150) cannot fail InsertFinding with an opaque constraint error.
		if confidence > 1.0 {
			confidence = 1.0
		}
		if confidence < 0 {
			confidence = 0
		}

		finding := &db.Finding{
			RuleID:         parseStringFlag(remaining, "rule-id"),
			Severity:       parseStringFlag(remaining, "severity"),
			Confidence:     confidence,
			Evidence:       parseStringFlag(remaining, "evidence"),
			Status:         parseStringFlag(remaining, "status"),
			FilePath:       parseStringFlag(remaining, "file"),
			LineNumber:     parseIntFlag(remaining, "line"),
			FunctionName:   parseStringFlag(remaining, "function"),
			Properties:     parseStringFlag(remaining, "properties"),
			Summary:        parseStringFlag(remaining, "summary"),
			Reasoning:      parseStringFlag(remaining, "reasoning"),
			FixStrategy:    parseStringFlag(remaining, "fix-strategy"),
			ExceptionCheck: parseStringFlag(remaining, "exception-check"),
			ScanID:         parseStringFlag(remaining, "scan-id"),
		}
		// The agent tool carries structured output (summary/reasoning/
		// fix_strategy/exception_check) inside the --properties JSON, since a
		// JSON string is single-line (newlines escaped) and survives argument
		// passing regardless of the shell. Fall back to those keys when the
		// dedicated flags are absent, so multi-line reasoning/fix code is not lost.
		finding.ApplyStructuredFromProperties()
		// The properties JSON was only the transport; the structured fields now
		// live in their dedicated columns. Drop the raw copy so the DB stays lean.
		finding.Properties = ""

		if finding.Severity == "" {
			finding.Severity = "info"
		} else {
			finding.Severity = strings.ToLower(finding.Severity)
		}
		finding.Status = strings.ToLower(finding.Status)

		cweNorm := strings.ToUpper(strings.TrimSpace(finding.RuleID))
		if cweNorm == "" {
			WriteErrorJSON("--write requires a non-empty --rule-id (CWE)")
			return 1
		}
		if !db.SupportedFindingCWEs[cweNorm] {
			WriteErrorJSON(fmt.Sprintf("unsupported rule_id %q: SecGuard pipeline does not detect this vulnerability type. Supported CWEs: %s. Agent-observed findings for unsupported types should be reported as observations, not persisted.", finding.RuleID, db.SupportedCWEsList()))
			return 1
		}

		// Validate scan_id exists so findings can never be silently attached to
		// a nonexistent scan (e.g. a stale or typo'd id from the agent). An
		// empty scan_id is allowed for backward compatibility with callers that
		// don't track scans, but we first try to inherit the current scan from
		// the `latest` pointer: without a scan the per-finding markdown has no
		// directory to live in, and losing it silently is exactly the failure
		// that left dismissed candidates sitting in findings/.
		scanIDSource := "explicit"
		if finding.ScanID == "" {
			scanIDSource = "none"
			if cwd, err := os.Getwd(); err == nil && cwd != "" {
				if latest := report.LatestScanID(cwd); latest != "" {
					if stats, serr := store.ListScanStats(ctx, latest); serr == nil && len(stats) > 0 {
						finding.ScanID = latest
						scanIDSource = "latest"
					}
				}
			}
		}
		if finding.ScanID != "" {
			stats, err := store.ListScanStats(ctx, finding.ScanID)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to validate scan_id: %v", err))
				return 1
			}
			if len(stats) == 0 {
				WriteErrorJSON(fmt.Sprintf("unknown scan_id %q: no scan_stats found for this id. Run 'secguard scan' first, or pass the scan_id from the scan output.", finding.ScanID))
				return 1
			}
		}

		id, err := store.UpsertFinding(ctx, finding)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write finding: %v", err))
			return 1
		}

		oc := syncPerFindingAfterWrite(remaining, finding)

		out := map[string]interface{}{
			"id":                 id,
			"status":             "ok",
			"scan_id":            finding.ScanID,
			"scan_id_source":     scanIDSource,
			"per_finding_path":   oc.Path,
			"per_finding_action": oc.Action,
		}
		if oc.Warning != "" {
			out["per_finding_warning"] = oc.Warning
			fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
		}
		WriteJSON(out)
		return 0
	}

	// --write-json <file> writes a whole batch of findings in ONE subprocess
	// call, idempotently (re-running updates, never duplicates). It is the CLI
	// path a Claude Code agent (no MCP secguard_report tool) uses instead of
	// generating a per-finding bash loop, which is slow and error-prone. The file
	// is a JSON array of objects with keys rule_id/severity/confidence/status/
	// file/line/function/summary/reasoning/exception_check/fix_strategy. `-` or a
	// missing value reads from stdin.
	if hasFlag(remaining, "write-json") {
		scanID := parseStringFlag(remaining, "scan-id")

		src := parseStringFlag(remaining, "write-json")
		var data []byte
		var err error
		if src == "" || src == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to read --write-json input: %v", err))
			return 1
		}

		type findingInput struct {
			RuleID         string  `json:"rule_id"`
			Severity       string  `json:"severity"`
			Confidence     float64 `json:"confidence"`
			Status         string  `json:"status"`
			File           string  `json:"file"`
			Line           int     `json:"line"`
			Function       string  `json:"function"`
			Summary        string  `json:"summary"`
			Reasoning      string  `json:"reasoning"`
			ExceptionCheck string  `json:"exception_check"`
			FixStrategy    string  `json:"fix_strategy"`
		}
		var inputs []findingInput
		if err := json.Unmarshal(data, &inputs); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to parse --write-json array: %v", err))
			return 1
		}

		written := make([]map[string]interface{}, 0, len(inputs))
		var errs []string
		var failedDetails []map[string]interface{}
		for i := range inputs {
			in := &inputs[i]
			confidence := in.Confidence
			if confidence > 1.0 {
				confidence /= 100.0
			}
			if confidence > 1.0 {
				confidence = 1.0
			}
			if confidence < 0 {
				confidence = 0
			}
			severity := strings.ToLower(in.Severity)
			if severity == "" {
				severity = "info"
			}

			cweNorm := strings.ToUpper(strings.TrimSpace(in.RuleID))
			if cweNorm == "" {
				errs = append(errs, fmt.Sprintf("%s:%d — empty rule_id", in.File, in.Line))
				continue
			}
			if !db.SupportedFindingCWEs[cweNorm] {
				errs = append(errs, fmt.Sprintf("%s:%d — unsupported rule_id %q", in.File, in.Line, in.RuleID))
				continue
			}

			f := &db.Finding{
				RuleID:         in.RuleID,
				Severity:       severity,
				Confidence:     confidence,
				Status:         strings.ToLower(in.Status),
				FilePath:       in.File,
				LineNumber:     in.Line,
				FunctionName:   in.Function,
				Summary:        in.Summary,
				Reasoning:      in.Reasoning,
				FixStrategy:    in.FixStrategy,
				ExceptionCheck: in.ExceptionCheck,
				ScanID:         scanID,
			}
			id, uerr := store.UpsertFinding(ctx, f)
			if uerr != nil {
				errClass := classifyWriteErr(uerr)
				errs = append(errs, fmt.Sprintf("%s:%d — %v", in.File, in.Line, uerr))
				failedDetails = append(failedDetails, map[string]interface{}{
					"file": in.File, "line": in.Line, "error_class": errClass, "message": uerr.Error(),
				})
				fmt.Fprintf(os.Stderr, "FATAL: finding write failed: %s:%d — [%s] %v\n", in.File, in.Line, errClass, uerr)
				continue
			}
			written = append(written, map[string]interface{}{
				"file": in.File, "line": in.Line, "id": id,
			})
		}

		out := map[string]interface{}{
			"status":           "ok",
			"findings_written": len(written),
			"written":          written,
			"scan_id":          scanID,
			"failed_count":     len(failedDetails),
		}
		if len(failedDetails) > 0 {
			out["failed_details"] = failedDetails
		}
		if len(errs) > 0 {
			out["status"] = "partial"
			out["errors"] = errs
		}
		WriteJSON(out)
		return 0
	}

	if hasFlag(remaining, "review") {
		findingID := int64(parseIntFlag(remaining, "id"))
		if findingID == 0 {
			WriteErrorJSON("--review requires --id=<finding_id>")
			return 1
		}
		reviewStatus := parseStringFlag(remaining, "review-status")
		reviewReasoning := parseStringFlag(remaining, "review-reasoning")
		switch reviewStatus {
		case "confirmed", "dismissed", "suspected-kept":
		default:
			WriteErrorJSON(fmt.Sprintf("invalid --review-status %q (expected confirmed|dismissed|suspected-kept)", reviewStatus))
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
		if reviewStatus == "suspected-kept" {
			finalStatus = "suspected"
		}
		// Re-send the structured content the first pass persisted, so the A5
		// review updates the verdict without wiping Summary/Reasoning/Fix
		// Strategy — and so a dismissal removes the file from findings/ rather
		// than leaving a confirmed-looking file behind.
		reviewed := *f
		reviewed.Status = finalStatus
		reviewed.ReviewStatus = ""
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
		WriteJSON(out)
		return 0
	}

	if hasFlag(remaining, "audit") {
		scanID := parseStringFlag(remaining, "scan-id")
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

		scanFindings, _ := store.ListFindingsByScanID(ctx, scanID)
		type vulnCounts struct {
			confirmed, suspected, dismissed int
		}
		countsByVuln := make(map[string]*vulnCounts)
		for _, f := range scanFindings {
			vt := planner.TypeForCWE(f.RuleID)
			if vt == "" {
				continue
			}
			if countsByVuln[vt] == nil {
				countsByVuln[vt] = &vulnCounts{}
			}
			switch f.EffectiveStatus() {
			case "confirmed":
				countsByVuln[vt].confirmed++
			case "suspected":
				countsByVuln[vt].suspected++
			case "dismissed":
				countsByVuln[vt].dismissed++
			}
		}

		audits := make([]vulnAuditEntry, 0, len(stats))
		for _, st := range stats {
			vc := countsByVuln[st.VulnType]
			if vc == nil {
				vc = &vulnCounts{}
			}
			audits = append(audits, vulnAuditEntry{
				VulnType:   st.VulnType,
				SeedCount:  st.SeedCount,
				FinalCount: st.FinalCount,
				Filters:    st.FilterChain,
				Confirmed:  vc.confirmed,
				Suspected:  vc.suspected,
				Dismissed:  vc.dismissed,
			})
		}

		outputDir := parseStringFlag(remaining, "output-dir")
		if outputDir != "" {
			auditPath := filepath.Join(outputDir, "audit-report.md")
			if err := writeAuditReport(auditPath, scanID, audits); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write audit report: %v", err))
				return 1
			}
			// Regenerate result.sarif from the AI's persisted findings so the
			// machine-readable report carries the post-A5 verdict + reasoning +
			// fix, not just the candidate-stage evidence.
			sarifPath := filepath.Join(outputDir, report.SarifFile)
			if err := report.WriteSarifFromFindings(sarifPath, "", scanFindings); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write result.sarif: %v", err))
				return 1
			}
			// Regenerate report.md from the AI's persisted findings so the
			// human-readable report shows confirmed + suspected verdicts, not
			// the candidate-stage leads that writeReport emitted at scan time.
			reportPath := filepath.Join(outputDir, report.ReportFile)
			if err := report.WriteReportFromFindings(reportPath, "", scanFindings); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write report.md: %v", err))
				return 1
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
				"vuln_count":      len(audits),
				"findings_synced": rec,
				"status":          "ok",
			}
			// Every converged candidate is supposed to receive a persisted
			// verdict. A nonzero remainder means verdicts exist only in the
			// agent's prose — the exact gap that made a console "已排除误报"
			// note disagree with the database and with findings/. Report it in
			// the same response the agent reads, not just inside the audit
			// markdown a human might never open.
			if unclassified := unclassifiedCandidates(audits); unclassified > 0 {
				out["unclassified_candidates"] = unclassified
				out["warning"] = fmt.Sprintf("%d converged candidate(s) have no persisted verdict — an exclusion stated only in prose is not recorded. Write a finding (confirmed|suspected|dismissed) for every candidate.", unclassified)
			}
			// A finding with no scan_id has no scan directory, so its verdict
			// file cannot be placed or reconciled. Surface it instead of
			// letting the review surface be quietly incomplete.
			if orphans := countFindingsWithoutScanID(ctx, store); orphans > 0 {
				out["findings_without_scan_id"] = orphans
				out["warning"] = fmt.Sprintf("%d finding(s) carry no scan_id and are missing from %s/ — re-write them with --scan-id", orphans, report.FindingsDir)
			}
			WriteJSON(out)
		} else {
			WriteJSON(map[string]interface{}{
				"scan_id": scanID,
				"audits":  audits,
			})
		}
		return 0
	}

	statusFilter := parseStringFlag(remaining, "status")

	findings, err := store.ListFindings(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list findings: %v", err))
		return 1
	}
	// Filter by the post-A5 effective verdict, not the raw first-pass status, so
	// a reviewed finding is listed under its final verdict (consistent with the
	// audit report, SARIF, and suppression index).
	if statusFilter != "" {
		filtered := make([]*db.Finding, 0, len(findings))
		for _, f := range findings {
			if f.EffectiveStatus() == statusFilter {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	if len(findings) == 0 {
		WriteJSON(map[string]interface{}{
			"findings": []interface{}{},
			"count":    0,
			"message":  "no findings in database; run 'secguard report --write ...' to persist findings after classifying candidates",
		})
		return 0
	}
	WriteJSON(findings)
	return 0
}

type vulnAuditEntry struct {
	VulnType   string `json:"vuln_type"`
	SeedCount  int    `json:"seed_count"`
	FinalCount int    `json:"final_count"`
	Filters    string `json:"filter_chain"`
	Confirmed  int    `json:"confirmed"`
	Suspected  int    `json:"suspected"`
	Dismissed  int    `json:"dismissed"`
}

func writeAuditReport(auditPath, scanID string, audits []vulnAuditEntry) error {
	if err := os.MkdirAll(filepath.Dir(auditPath), 0755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# SecGuard Audit Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan ID:** `%s`\n\n", scanID))
	b.WriteString("## Per-Skill Pipeline Statistics\n\n")
	b.WriteString("| Vulnerability Type | Seed | Final | AI Confirmed | AI Suspected | AI Dismissed | Filter Efficiency | AI Accuracy |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")

	totalSeed, totalFinal, totalConfirmed, totalSuspected, totalDismissed := 0, 0, 0, 0, 0
	for _, a := range audits {
		filterEff := "n/a"
		if a.SeedCount > 0 {
			filterEff = fmt.Sprintf("%.0f%%", float64(a.SeedCount-a.FinalCount)/float64(a.SeedCount)*100)
		}
		aiAcc := "n/a"
		classified := a.Confirmed + a.Dismissed
		if classified > 0 {
			aiAcc = fmt.Sprintf("%.0f%%", float64(a.Confirmed)/float64(classified)*100)
		}
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %s | %s |\n",
			a.VulnType, a.SeedCount, a.FinalCount, a.Confirmed, a.Suspected, a.Dismissed, filterEff, aiAcc))
		totalSeed += a.SeedCount
		totalFinal += a.FinalCount
		totalConfirmed += a.Confirmed
		totalSuspected += a.Suspected
		totalDismissed += a.Dismissed
	}

	b.WriteString(fmt.Sprintf("| **TOTAL** | **%d** | **%d** | **%d** | **%d** | **%d** |", totalSeed, totalFinal, totalConfirmed, totalSuspected, totalDismissed))
	if totalSeed > 0 {
		b.WriteString(fmt.Sprintf(" **%.0f%%** |", float64(totalSeed-totalFinal)/float64(totalSeed)*100))
	} else {
		b.WriteString(" n/a |")
	}
	totalClassified := totalConfirmed + totalDismissed
	if totalClassified > 0 {
		b.WriteString(fmt.Sprintf(" **%.0f%%** |\n\n", float64(totalConfirmed)/float64(totalClassified)*100))
	} else {
		b.WriteString(" n/a |\n\n")
	}

	// AI Value Summary: make the human impact of the AI classification layer
	// explicit and auditable. Every converged candidate should receive a
	// classification; a nonzero "without AI classification" count is a process
	// gap (e.g. a candidate whose skill was not loaded), not a design feature.
	classifiedByAI := totalConfirmed + totalSuspected + totalDismissed
	unclassified := totalFinal - classifiedByAI
	if unclassified < 0 {
		unclassified = 0
	}
	b.WriteString("## AI Value Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	fmt.Fprintf(&b, "| Raw evidence seeds | %d |\n", totalSeed)
	fmt.Fprintf(&b, "| Converged candidates (after pipeline filters) | %d |\n", totalFinal)
	fmt.Fprintf(&b, "| Candidates classified by AI | %d |\n", classifiedByAI)
	fmt.Fprintf(&b, "| Candidates without AI classification | %d |\n", unclassified)
	fmt.Fprintf(&b, "| AI confirmed (actionable, with fix suggestion) | %d |\n", totalConfirmed)
	fmt.Fprintf(&b, "| AI suspected (needs human decision) | %d |\n", totalSuspected)
	fmt.Fprintf(&b, "| AI dismissed (false positives, evidence recorded) | %d |\n", totalDismissed)
	fmt.Fprintf(&b, "| Actionable findings for human review | %d |\n", totalConfirmed+totalSuspected)
	if totalSeed > 0 {
		fmt.Fprintf(&b, "| Pipeline filter efficiency | %.0f%% |\n", float64(totalSeed-totalFinal)/float64(totalSeed)*100)
	} else {
		b.WriteString("| Pipeline filter efficiency | n/a |\n")
	}
	if totalClassified > 0 {
		fmt.Fprintf(&b, "| AI accuracy (confirmed / confirmed+dismissed) | %.0f%% |\n\n", float64(totalConfirmed)/float64(totalClassified)*100)
	} else {
		b.WriteString("| AI accuracy (confirmed / confirmed+dismissed) | n/a |\n\n")
	}

	b.WriteString("## Filter Chain Details\n\n")
	for _, a := range audits {
		b.WriteString(fmt.Sprintf("### %s\n\n", a.VulnType))
		b.WriteString(fmt.Sprintf("- **Seed count:** %d\n", a.SeedCount))
		b.WriteString(fmt.Sprintf("- **Final count:** %d\n", a.FinalCount))
		if a.Filters != "" {
			b.WriteString(fmt.Sprintf("- **Filter chain:** `%s`\n", a.Filters))
		}
		b.WriteString(fmt.Sprintf("- **AI classification:** confirmed=%d, suspected=%d, dismissed=%d\n\n", a.Confirmed, a.Suspected, a.Dismissed))
	}

	return os.WriteFile(auditPath, []byte(b.String()), 0644)
}

func resolveScanDir(args []string, scanID string) string {
	outputDir := parseStringFlag(args, "output-dir")
	if outputDir != "" {
		return outputDir
	}
	if scanID == "" {
		return ""
	}
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		return ""
	}
	return filepath.Join(cwd, report.CodeagentDir, report.ProductDir, report.ScansDir, scanID)
}

// perFindingOutcome carries what the per-finding markdown writer did, plus a
// human-readable warning when it did nothing. The warning is the point: before
// 0.3.6 a failed rewrite was silent, so a whole classification pass could land
// in the DB while findings/ still showed unclassified candidates.
type perFindingOutcome struct {
	Path    string
	Action  string
	Warning string
}

func syncPerFindingAfterWrite(args []string, finding *db.Finding) perFindingOutcome {
	if finding.FilePath == "" || finding.LineNumber <= 0 {
		return perFindingOutcome{Action: "skipped", Warning: "per-finding markdown not written: finding carries no file/line"}
	}
	scanDir := resolveScanDir(args, finding.ScanID)
	if scanDir == "" {
		return perFindingOutcome{Action: "skipped", Warning: fmt.Sprintf(
			"per-finding markdown not written: no scan directory resolved — pass --scan-id (or --output-dir) so the verdict file lands under %s/<vuln-type>/", report.FindingsDir)}
	}
	if _, err := os.Stat(scanDir); err != nil {
		return perFindingOutcome{Action: "skipped", Warning: fmt.Sprintf(
			"per-finding markdown not written: scan dir %s is not readable (%v) — pass --output-dir pointing at the scan directory", scanDir, err)}
	}
	vulnType := planner.TypeForCWE(finding.RuleID)
	if vulnType == "" {
		return perFindingOutcome{Action: "skipped", Warning: fmt.Sprintf(
			"per-finding markdown not written: rule_id %q maps to no pipeline vulnerability type", finding.RuleID)}
	}
	res, err := report.SyncPerFinding(scanDir, vulnType, finding.FilePath, finding.LineNumber, report.PerFindingUpdate{
		Summary:        finding.Summary,
		Reasoning:      finding.Reasoning,
		FixStrategy:    finding.FixStrategy,
		ExceptionCheck: finding.ExceptionCheck,
		Status:         finding.EffectiveStatus(),
		Severity:       finding.Severity,
		Confidence:     finding.Confidence,
		FunctionName:   finding.FunctionName,
		Evidence:       finding.Evidence,
	})
	if err != nil {
		return perFindingOutcome{Action: "error", Warning: fmt.Sprintf("per-finding markdown failed: %v", err)}
	}
	oc := perFindingOutcome{Path: res.Path, Action: res.Action}
	if res.Verdict == "" {
		oc.Warning = fmt.Sprintf("status %q carries no verdict, so %s/ was left untouched (expected confirmed|suspected|dismissed)",
			finding.Status, report.FindingsDir)
	}
	return oc
}

// countFindingsWithoutScanID reports how many findings cannot be placed in any
// scan's findings/ directory because they carry no scan_id.
func countFindingsWithoutScanID(ctx context.Context, store db.Store) int {
	all, err := store.ListFindings(ctx)
	if err != nil {
		return 0
	}
	n := 0
	for _, f := range all {
		if f.ScanID == "" {
			n++
		}
	}
	return n
}

// unclassifiedCandidates counts converged candidates that received no persisted
// verdict at all. It is the machine-checkable form of "every candidate must get
// a finding": a bulk exclusion the agent only narrated shows up here.
func unclassifiedCandidates(audits []vulnAuditEntry) int {
	total := 0
	for _, a := range audits {
		remainder := a.FinalCount - (a.Confirmed + a.Suspected + a.Dismissed)
		if remainder > 0 {
			total += remainder
		}
	}
	return total
}
