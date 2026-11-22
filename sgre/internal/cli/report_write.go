package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// runReportWrite handles `report --write` (the single-finding write path).
func runReportWrite(ctx context.Context, store db.Store, remaining []string) int {
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
		VulnType:       parseStringFlag(remaining, "vuln-type"),
		Severity:       parseStringFlag(remaining, "severity"),
		Confidence:     confidence,
		Evidence:       parseStringFlag(remaining, "evidence"),
		Status:         parseStringFlag(remaining, "status"),
		FilePath:       parseStringFlag(remaining, "file"),
		LineNumber:     parseIntFlag(remaining, "line"),
		FunctionName:   parseStringFlag(remaining, "function"),
		Variable:       parseStringFlag(remaining, "variable"),
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
	// The single --write path enforces the SAME verdict whitelist as the
	// batch --write-json path, so an AI can never persist the pipeline
	// intermediate state `open` (or an empty status) as a finding.
	if status, serr := normalizeAIVerdict(finding.Status); serr != nil {
		WriteErrorJSON(serr.Error())
		return 1
	} else {
		finding.Status = status
	}

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
	// An unindexed absolute path resolves to "" and is rejected (issue #275
	// P1-6): it must not become an arbitrary-file read in a later audit.
	finding.FilePath = resolveFindingFilePath(ctx, store, finding.FilePath, nil)
	if finding.FilePath == "" {
		WriteErrorJSON("file path is not an indexed file of this scan")
		return 1
	}

	// Content-addressed identity for cross-scan dedup (incremental review).
	// Computed from the resolved absolute path (matching the --write-json
	// batch path) so the fingerprint is stable across path spellings.
	finding.Fingerprint = computeFingerprint(finding.RuleID, finding.FilePath, finding.FunctionName, finding.LineNumber)

	// A dismissed verdict writes no findings row, but it MUST land in the
	// candidate_verdicts ledger exactly like the batch --write-json path:
	// otherwise the sequential path's dismissals are invisible to recovery
	// ("classified and dismissed" vs "never classified").
	if finding.Status == "dismissed" {
		dismissedType := finding.VulnType
		if dismissedType == "" {
			dismissedType = planner.TypeForCWE(finding.RuleID)
		}
		dismissedWritten := false
		if dismissedType != "" && finding.ScanID != "" {
			if _, verr := store.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
				ScanID:       finding.ScanID,
				VulnType:     dismissedType,
				RuleID:       strings.ToUpper(strings.TrimSpace(finding.RuleID)),
				FilePath:     finding.FilePath,
				LineNumber:   finding.LineNumber,
				FunctionName: finding.FunctionName,
				Variable:     finding.Variable,
				Verdict:      "dismissed",
				Reason:       finding.Reasoning,
			}); verr != nil {
				WriteErrorJSON(fmt.Sprintf("failed to record dismissed verdict in candidate_verdicts: %v", verr))
				return 1
			}
			dismissedWritten = true
		}
		oc := syncPerFindingAfterWrite(remaining, finding)
		out := map[string]interface{}{
			"status":              "ok",
			"dismissed":           true,
			"dismissed_written":   dismissedWritten,
			"dismissed_persisted": dismissedWritten,
			"scan_id":             finding.ScanID,
			"scan_id_source":      scanIDSource,
			"per_finding_path":    oc.Path,
			"per_finding_action":  oc.Action,
		}
		if oc.Warning != "" {
			out["per_finding_warning"] = oc.Warning
			fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
		}
		_ = WriteJSON(out)
		return 0
	}

	var id int64
	var duplicate bool
	// Probe and upsert in one IMMEDIATE transaction so the duplicate flag is
	// exact under concurrent writers: the second writer sees the first's row
	// and reports an idempotent update, never a silent second finding.
	if txErr := store.WithImmediateTx(ctx, func(tx db.Store) error {
		_, found, derr := tx.FindingIDByLocationKey(ctx, finding.ScanID, finding.RuleID, finding.FilePath, finding.LineNumber, finding.Variable)
		if derr != nil {
			return derr
		}
		duplicate = found
		var uerr error
		id, uerr = tx.UpsertFinding(ctx, finding)
		return uerr
	}); txErr != nil {
		WriteErrorJSON(fmt.Sprintf("failed to write finding: %v", txErr))
		return 1
	}
	if duplicate {
		fmt.Fprintf(os.Stderr, "duplicate: finding already exists at %s:%d — updated in place (idempotent write, not a second finding)\n", finding.FilePath, finding.LineNumber)
	}

	oc := syncPerFindingAfterWrite(remaining, finding)

	out := map[string]interface{}{
		"id":                 id,
		"status":             "ok",
		"duplicate":          duplicate,
		"scan_id":            finding.ScanID,
		"scan_id_source":     scanIDSource,
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

// runReportWriteJSON handles `report --write-json` (the batch write path).
//
// --write-json <file> writes a whole batch of findings in ONE subprocess
// call, idempotently (re-running updates, never duplicates). It is the CLI
// path a Claude Code agent (no MCP secguard_report tool) uses instead of
// generating a per-finding bash loop, which is slow and error-prone. The file
// is a JSON array of objects with keys rule_id/severity/confidence/status/
// file/line/function/summary/reasoning/exception_check/fix_strategy. `-` or a
// missing value reads from stdin.
func runReportWriteJSON(ctx context.Context, store db.Store, remaining []string) int {
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

	inputs, embeddedScanID, salvaged, perr := parseWriteJSONInput(data)
	if perr != nil {
		WriteErrorJSON(fmt.Sprintf("failed to parse --write-json input: %v. %s", perr, writeJSONShapeHint))
		return 1
	}

	// An explicit --scan-id wins; otherwise honour a scan_id embedded in an
	// object envelope, so the tolerated wrapper is not merely accepted but
	// attached to the right scan.
	scanID := parseStringFlag(remaining, "scan-id")
	if scanID == "" {
		scanID = embeddedScanID
	}

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

	written := make([]map[string]interface{}, 0, len(inputs))
	var errs []string
	var failedDetails []map[string]interface{}
	// Fetch the indexed file list once so path resolution for a large batch
	// (e.g. 255 null-deref findings) does not re-scan the files table per row.
	// A failure here would silently degrade path resolution to the raw
	// (relative/truncated) agent-supplied path, which then bypasses the
	// uq_finding_loc idempotency key's absolute-path normalization. Fail the
	// batch instead (writes are idempotent, so a re-run is safe).
	allFiles, listErr := store.ListFiles(ctx)
	if listErr != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list files for path resolution: %v", listErr))
		return 1
	}

	// First pass (read-only): validate every row and resolve its path to the
	// indexed absolute path, so the write pass below is pure upserts.
	type pendingWrite struct {
		in *findingInput
		f  *db.Finding
	}
	pending := make([]*pendingWrite, 0, len(inputs))
	writtenFindings := []*db.Finding{}
	type dismissedWrite struct {
		verdict *db.CandidateVerdict
		file    string
		line    int
	}
	var dismissedPending []dismissedWrite
	skippedDismissed := 0
	for i := range inputs {
		in := &inputs[i]
		in.normalizeAliases()
		// A finding with no location cannot be keyed, written to findings/,
		// or reconciled — the scan's auto-confirm path explicitly refuses
		// one. Reject it here with the expected keys named instead of
		// persisting a file_path='' line=0 row and exiting 0.
		if strings.TrimSpace(in.File) == "" || in.Line <= 0 {
			errs = append(errs, fmt.Sprintf("entry %d: missing location — expected \"file\" (string) and \"line\" (positive integer); the DB column names file_path/line_number are accepted as aliases", i))
			continue
		}
		// A finding's source must be one of the indexed files: an absolute
		// path that is not in the files table would otherwise be read back by
		// `report --audit` and embedded into the report (issue #275 P1-6).
		resolvedFile := resolveFindingFilePath(ctx, store, in.File, allFiles)
		if resolvedFile == "" {
			errs = append(errs, fmt.Sprintf("entry %d: file %q is not an indexed file of this scan", i, in.File))
			continue
		}
		confidence := float64(in.Confidence)
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

		// 校验 status 只能是二元裁决；非法值（如 pipeline 中间态 open）立即
		// 拒绝整批，而非 partial 跳过导致静默丢失。技能文件里把误报写成
		// `false-positive`，这是 `dismissed` 的同义判定——归一化后落库，避免
		// 子代理照抄技能原文导致整批被拒。
		status, serr := normalizeAIVerdict(in.Status)
		if serr != nil {
			WriteErrorJSON(fmt.Sprintf("invalid status %q at %s:%d — expected confirmed|dismissed", in.Status, in.File, in.Line))
			return 1
		}
		if status == "dismissed" {
			skippedDismissed++
			// Dismissed candidates are not persisted as findings, but the
			// verdict MUST land in the candidate_verdicts ledger — in the SAME
			// immediate transaction as the confirmed rows below, never as a
			// best-effort autocommit whose failure still returned status:ok.
			// Without that ledger row, recovery cannot tell "classified and
			// dismissed" from "never classified".
			dismissedType := in.VulnType
			if dismissedType == "" {
				dismissedType = planner.TypeForCWE(in.RuleID)
			}
			if dismissedType != "" {
				dismissedPending = append(dismissedPending, dismissedWrite{
					verdict: &db.CandidateVerdict{
						ScanID:       scanID,
						VulnType:     dismissedType,
						RuleID:       strings.ToUpper(strings.TrimSpace(in.RuleID)),
						FilePath:     resolvedFile,
						LineNumber:   in.Line,
						FunctionName: in.Function,
						Variable:     in.Variable,
						Verdict:      "dismissed",
						Reason:       in.Reasoning,
					},
					file: in.File,
					line: in.Line,
				})
			}
			if scanDir := resolveScanDir(remaining, scanID); scanDir != "" {
				if dismissedType != "" {
					if _, serr := report.SyncPerFinding(scanDir, dismissedType, resolvedFile, in.Line, report.PerFindingUpdate{
						Status:       "dismissed",
						Reasoning:    in.Reasoning,
						FunctionName: in.Function,
						Variable:     in.Variable,
						CWE:          in.RuleID,
					}); serr != nil {
						fmt.Fprintf(os.Stderr, "warning: annotate dismissed candidate %s:%d: %v\n", resolvedFile, in.Line, serr)
					}
				}
			}
			continue
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

		vt := in.VulnType
		if vt == "" {
			vt = planner.TypeForCWE(in.RuleID)
		}
		f := &db.Finding{
			RuleID:         cweNorm,
			VulnType:       vt,
			Severity:       severity,
			Confidence:     confidence,
			Status:         status,
			FilePath:       in.File,
			LineNumber:     in.Line,
			FunctionName:   in.Function,
			Variable:       in.Variable,
			Summary:        in.Summary,
			Reasoning:      in.Reasoning,
			FixStrategy:    in.FixStrategy,
			ExceptionCheck: in.ExceptionCheck,
			ScanID:         scanID,
		}
		f.FilePath = resolvedFile
		f.Fingerprint = computeFingerprint(f.RuleID, f.FilePath, f.FunctionName, f.LineNumber)
		pending = append(pending, &pendingWrite{in: in, f: f})
	}

	// Second pass: write every finding in ONE transaction, so a large batch
	// commits once (one commit record + one write-lock acquisition) instead of
	// per-row autocommit (one implicit BEGIN/COMMIT + lock round-trip per row)
	// — the per-row autocommit was the write-side half of the null-deref
	// slowness. Use WithImmediateTx (BEGIN IMMEDIATE) rather than WithTx so
	// the write lock is acquired exactly ONCE up front: under the concurrent
	// subagent write storm a deferred transaction would re-wait busy_timeout
	// and the app-layer retry per row (~40s × N rows), which is what turned a
	// contended persist into a multi-minute/hang. BEGIN IMMEDIATE makes it
	// serialize fast or fail after one busy_timeout with a clean error.
	duplicates := 0
	dismissedWritten := 0
	dismissedFailed := 0
	if txErr := store.WithImmediateTx(ctx, func(tx db.Store) error {
		for _, p := range pending {
			duplicate := false
			if priorID, found, derr := tx.FindingIDByLocationKey(ctx, p.f.ScanID, p.f.RuleID, p.f.FilePath, p.f.LineNumber, p.f.Variable); derr != nil {
				errClass := classifyWriteErr(derr)
				errs = append(errs, fmt.Sprintf("%s:%d — duplicate probe: %v", p.in.File, p.in.Line, derr))
				failedDetails = append(failedDetails, map[string]interface{}{
					"file": p.in.File, "line": p.in.Line, "error_class": errClass, "message": derr.Error(),
				})
				fmt.Fprintf(os.Stderr, "FATAL: finding duplicate probe failed: %s:%d — [%s] %v\n", p.in.File, p.in.Line, errClass, derr)
				continue
			} else if found {
				duplicate = true
				duplicates++
				fmt.Fprintf(os.Stderr, "duplicate: finding already exists at %s:%d (id %d) — updated in place (idempotent write, not a second finding)\n", p.in.File, p.in.Line, priorID)
			}
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
				"file": p.in.File, "line": p.in.Line, "id": id, "duplicate": duplicate,
			})
			writtenFindings = append(writtenFindings, p.f)
		}
		for _, dw := range dismissedPending {
			if _, uerr := tx.UpsertCandidateVerdict(ctx, dw.verdict); uerr != nil {
				errClass := classifyWriteErr(uerr)
				errs = append(errs, fmt.Sprintf("dismissed verdict %s:%d — %v", dw.file, dw.line, uerr))
				failedDetails = append(failedDetails, map[string]interface{}{
					"file": dw.file, "line": dw.line, "error_class": errClass, "message": uerr.Error(),
				})
				fmt.Fprintf(os.Stderr, "FATAL: dismissed verdict write failed: %s:%d — [%s] %v\n", dw.file, dw.line, errClass, uerr)
				dismissedFailed++
				continue
			}
			dismissedWritten++
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

	// Mirror the single --write path: sync each persisted finding to its
	// per-finding markdown so findings/<type>/<file>.md never stays stale
	// relative to the DB after a batch write.
	for _, f := range writtenFindings {
		if oc := syncPerFindingAfterWrite(remaining, f); oc.Warning != "" {
			fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
		}
	}

	out := map[string]interface{}{
		"status":              "ok",
		"findings_written":    len(written),
		"duplicates":          duplicates,
		"skipped_dismissed":   skippedDismissed,
		"dismissed_written":   dismissedWritten,
		"dismissed_persisted": dismissedWritten,
		"dismissed_failed":    dismissedFailed,
		"written":             written,
		"scan_id":             scanID,
		"failed_count":        len(errs),
	}
	if len(failedDetails) > 0 {
		out["failed_details"] = failedDetails
	}
	if salvaged {
		out["salvaged"] = true
		out["truncated"] = true
		out["salvaged_count"] = len(inputs)
		out["status"] = "partial"
		out["warning"] = "input JSON was truncated/invalid; only the complete leading findings were persisted — this batch is NOT a completion proof, re-write the full batch"
	}
	if len(errs) > 0 {
		out["status"] = "partial"
		out["errors"] = errs
	}
	_ = WriteJSON(out)
	// A partial write is a failed write: exit non-zero so a CI gate keyed on
	// the exit code never mistakes dropped findings for success. errs (not
	// failedDetails) is the full set of dropped rows — it also covers the
	// validation skips (empty/unsupported rule_id) that `continue` before the
	// write pass, which failedDetails alone would miss.
	if len(errs) > 0 || salvaged {
		return 1
	}
	return 0
}
