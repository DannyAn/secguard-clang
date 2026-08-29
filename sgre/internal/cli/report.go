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

// resolveFindingFilePath maps an agent-supplied `file` (absolute, repo-relative,
// or a truncated tail the agent copied out of report.md's shortFile column) back
// to the canonical absolute path stored in the files table. The suffix fallback
// is best-effort: when nothing resolves the input is returned unchanged, so a
// finding whose source cannot be located degrades to "no code context" in the
// SARIF/xlsx instead of being silently rewritten to a wrong path.
//
// files is the pre-fetched indexed file list; pass it to amortize ListFiles
// across a whole --write-json batch. When nil, it is fetched lazily (fine for a
// single --write call).
func resolveFindingFilePath(ctx context.Context, store db.Store, file string, files []*db.File) string {
	if file == "" || filepath.IsAbs(file) {
		return file
	}
	if files == nil {
		files, _ = store.ListFiles(ctx)
	}
	needle := string(filepath.Separator) + filepath.Clean(file)
	var best string
	for _, f := range files {
		if f.Path == file || strings.HasSuffix(f.Path, needle) {
			if best == "" || len(f.Path) < len(best) {
				best = f.Path
			}
		}
	}
	if best != "" {
		return best
	}
	return file
}

// dedupeAndNormalizeFindings normalizes every finding's file path to the indexed
// absolute path, then collapses rows that differ only by path spelling (absolute
// vs the truncated/relative tail the agent copied out of report.md). That
// double-write artifact made result.sarif list one vulnerability type twice
// (once per path spelling), because the idempotency key includes file_path.
// Keeping the first row per canonical (scan_id, rule_id, abs path, line,
// function) restores one finding per location.
func dedupeAndNormalizeFindings(ctx context.Context, store db.Store, findings []*db.Finding) []*db.Finding {
	if len(findings) == 0 {
		return findings
	}
	files, _ := store.ListFiles(ctx)
	seen := make(map[string]bool, len(findings))
	out := make([]*db.Finding, 0, len(findings))
	for _, f := range findings {
		f.FilePath = resolveFindingFilePath(ctx, store, f.FilePath, files)
		key := f.ScanID + "\x00" + f.RuleID + "\x00" + f.FilePath + "\x00" + strconv.Itoa(f.LineNumber) + "\x00" + f.FunctionName
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
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
		// Content-addressed identity for cross-scan dedup (incremental review).
		finding.Fingerprint = computeFingerprint(finding.RuleID, finding.FilePath, finding.FunctionName, finding.LineNumber)

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

		// Normalize a relative/truncated agent-supplied file path to the indexed
		// absolute path, so the verdict markdown, result.sarif and result.xlsx can
		// all re-locate the source instead of emitting "Unable to find <file>".
		finding.FilePath = resolveFindingFilePath(ctx, store, finding.FilePath, nil)

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

		// Resolve and validate scan_id with the SAME rules as the single `--write`
		// path, so a batch can never be silently attached to a typo'd/nonexistent
		// scan (and an empty scan_id still inherits the current scan from `latest`
		// for backward compatibility). Without this, a wrong scan_id writes every
		// finding into a dead scan that the orchestrator's `--audit --scan-id`
		// never reads back — the same silent false-negative this check prevents in
		// the single-write path.
		if scanID == "" {
			if cwd, err := os.Getwd(); err == nil && cwd != "" {
				if latest := report.LatestScanID(cwd); latest != "" {
					if stats, serr := store.ListScanStats(ctx, latest); serr == nil && len(stats) > 0 {
						scanID = latest
					}
				}
			}
		}
		if scanID != "" {
			stats, err := store.ListScanStats(ctx, scanID)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to validate scan_id: %v", err))
				return 1
			}
			if len(stats) == 0 {
				WriteErrorJSON(fmt.Sprintf("unknown scan_id %q: no scan_stats found for this id. Run 'secguard scan' first, or pass the scan_id from the scan output.", scanID))
				return 1
			}
		}

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
		// Fetch the indexed file list once so path resolution for a large batch
		// (e.g. 255 null-deref findings) does not re-scan the files table per row.
		allFiles, _ := store.ListFiles(ctx)

		// First pass (read-only): validate every row and resolve its path to the
		// indexed absolute path, so the write pass below is pure upserts.
		type pendingWrite struct {
			in *findingInput
			f  *db.Finding
		}
		pending := make([]*pendingWrite, 0, len(inputs))
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
			f.FilePath = resolveFindingFilePath(ctx, store, f.FilePath, allFiles)
			f.Fingerprint = computeFingerprint(f.RuleID, f.FilePath, f.FunctionName, f.LineNumber)
			pending = append(pending, &pendingWrite{in: in, f: f})
		}

		// Second pass: write every finding in ONE transaction, so a large batch
		// commits once (one commit record + one write-lock acquisition) instead of
		// per-row autocommit (one implicit BEGIN/COMMIT + lock round-trip per row)
		// — the per-row autocommit was the write-side half of the null-deref
		// slowness.
		if txErr := store.WithTx(ctx, func(tx db.Store) error {
			for _, p := range pending {
				id, uerr := tx.UpsertFinding(ctx, p.f)
				if uerr != nil {
					errClass := classifyWriteErr(uerr)
					errs = append(errs, fmt.Sprintf("%s:%d — %v", p.in.File, p.in.Line, uerr))
					failedDetails = append(failedDetails, map[string]interface{}{
						"file": p.in.File, "line": p.in.Line, "error_class": errClass, "message": uerr.Error(),
					})
					fmt.Fprintf(os.Stderr, "FATAL: finding write failed: %s:%d — [%s] %v\n", p.in.File, p.in.Line, errClass, uerr)
					continue
				}
				written = append(written, map[string]interface{}{
					"file": p.in.File, "line": p.in.Line, "id": id,
				})
			}
			return nil
		}); txErr != nil {
			errClass := classifyWriteErr(txErr)
			errs = append(errs, fmt.Sprintf("batch commit — %v", txErr))
			failedDetails = append(failedDetails, map[string]interface{}{
				"error_class": errClass, "message": txErr.Error(),
			})
			fmt.Fprintf(os.Stderr, "FATAL: finding batch commit failed: [%s] %v\n", errClass, txErr)
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

	// --review-json <file> records the A5 second-round verdicts for a WHOLE batch
	// of suspected findings in ONE subprocess + ONE transaction, instead of the
	// per-finding `--review` loop that spawns a subprocess and opens SQLite per
	// row (the slow path that stretched a high-volume type like null-deref to
	// tens of minutes). Input is a JSON array of {id, review_status,
	// review_reasoning}. `-` or a missing value reads from stdin.
	if hasFlag(remaining, "review-json") {
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
		var errs []string
		err = store.WithTx(ctx, func(tx db.Store) error {
			for _, in := range inputs {
				switch in.ReviewStatus {
				case "confirmed", "dismissed", "suspected-kept":
				default:
					errs = append(errs, fmt.Sprintf("finding %d — invalid review_status %q", in.ID, in.ReviewStatus))
					continue
				}
				if in.ID == 0 {
					errs = append(errs, "missing id in review entry")
					continue
				}
				if uerr := tx.UpdateFindingReview(ctx, in.ID, in.ReviewStatus, in.ReviewReasoning); uerr != nil {
					errs = append(errs, fmt.Sprintf("finding %d — %v", in.ID, uerr))
					continue
				}
				reviewed = append(reviewed, map[string]interface{}{
					"id": in.ID, "review_status": in.ReviewStatus,
				})
			}
			return nil
		})
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to commit review batch: %v", err))
			return 1
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
		// Collapse duplicate rows that differ only by file-path spelling (the
		// absolute vs truncated double-write), and normalize paths to absolute so
		// every downstream report resolves source + embeds code context.
		scanFindings = dedupeAndNormalizeFindings(ctx, store, scanFindings)
		type vulnCounts struct {
			confirmed, suspected, dismissed, autoConfirmed int
		}
		countsByVuln := make(map[string]*vulnCounts)
		unreviewedSuspected := 0
		for _, f := range scanFindings {
			vt := planner.TypeForCWE(f.RuleID)
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
			if f.Status == db.StatusAutoConfirmed {
				countsByVuln[vt].autoConfirmed++
				continue
			}
			// A `suspected` finding whose A5 second-round never ran is an
			// incomplete verdict: it is excluded from every final export, and the
			// orchestrator must be told so it can re-dispatch the A5 pass instead
			// of shipping a scan that silently dropped its suspected residue.
			if f.Status == "suspected" && f.ReviewStatus == "" {
				unreviewedSuspected++
			}
			switch f.FinalStatus() {
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
				VulnType:      st.VulnType,
				SeedCount:     st.SeedCount,
				FinalCount:    st.FinalCount,
				Filters:       st.FilterChain,
				Confirmed:     vc.confirmed,
				Suspected:     vc.suspected,
				Dismissed:     vc.dismissed,
				AutoConfirmed: vc.autoConfirmed,
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
			// Regenerate result.xlsx from the same persisted findings: a one-way
			// export for the development team to locate, analyze, and confirm
			// every actionable finding inside a spreadsheet (dismissed excluded).
			xlsxPath := filepath.Join(outputDir, report.ResultXlsxFile)
			if err := report.WriteXlsxFromFindings(xlsxPath, "", scanFindings); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write result.xlsx: %v", err))
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
				"xlsx_path":       xlsxPath,
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
			// A `suspected` verdict that never went through the A5 second round is
			// incomplete, so it is excluded from result.sarif / result.xlsx /
			// report.md / findings/ rather than shipped as a final suspicion. Tell
			// the orchestrator explicitly so it can re-run A5 before finalizing.
			if unreviewedSuspected > 0 {
				out["unreviewed_suspected"] = unreviewedSuspected
				out["warning"] = fmt.Sprintf("%d suspected finding(s) were never A5-reviewed and are excluded from result.sarif/result.xlsx — run the A5 second round (confirmed|dismissed|suspected-kept) before finalizing.", unreviewedSuspected)
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
	VulnType      string `json:"vuln_type"`
	SeedCount     int    `json:"seed_count"`
	FinalCount    int    `json:"final_count"`
	Filters       string `json:"filter_chain"`
	Confirmed     int    `json:"confirmed"`
	Suspected     int    `json:"suspected"`
	Dismissed     int    `json:"dismissed"`
	AutoConfirmed int    `json:"auto_confirmed"`
}

func writeAuditReport(auditPath, scanID string, audits []vulnAuditEntry) error {
	if err := os.MkdirAll(filepath.Dir(auditPath), 0755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# SecGuard Audit Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan ID:** `%s`\n\n", scanID))
	b.WriteString("## Per-Skill Pipeline Statistics\n\n")
	b.WriteString("| Vulnerability Type | Seed | Final | Auto-confirmed | AI Confirmed | AI Suspected | AI Dismissed | Filter Efficiency | AI Accuracy |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")

	totalSeed, totalFinal, totalAutoConfirmed, totalConfirmed, totalSuspected, totalDismissed := 0, 0, 0, 0, 0, 0
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
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %d | %s | %s |\n",
			a.VulnType, a.SeedCount, a.FinalCount, a.AutoConfirmed, a.Confirmed, a.Suspected, a.Dismissed, filterEff, aiAcc))
		totalSeed += a.SeedCount
		totalFinal += a.FinalCount
		totalAutoConfirmed += a.AutoConfirmed
		totalConfirmed += a.Confirmed
		totalSuspected += a.Suspected
		totalDismissed += a.Dismissed
	}

	b.WriteString(fmt.Sprintf("| **TOTAL** | **%d** | **%d** | **%d** | **%d** | **%d** | **%d** |", totalSeed, totalFinal, totalAutoConfirmed, totalConfirmed, totalSuspected, totalDismissed))
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
	fmt.Fprintf(&b, "| Auto-confirmed by pipeline (no AI review) | %d |\n", totalAutoConfirmed)
	fmt.Fprintf(&b, "| Candidates needing AI review (suspected/possible) | %d |\n", totalFinal)
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
		b.WriteString(fmt.Sprintf("- **AI classification:** auto-confirmed=%d, confirmed=%d, suspected=%d, dismissed=%d\n\n", a.AutoConfirmed, a.Confirmed, a.Suspected, a.Dismissed))
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
