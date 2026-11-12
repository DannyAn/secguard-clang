package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DannyAn/secguard-clang/internal/build"
	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/git"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// scanIDPattern validates the basename of an explicit --output-dir to prevent
// path traversal and ensure the dir name matches the scan_id format that
// report.generateScanID produces: sc_YYYY-MM-DD_HHMMSS_xxxxxx (6-char suffix).
// The sc_ prefix ensures the `latest` symlink sorts before all scan dirs
// (lexicographically 'l' < 's'), so latest is always first in directory listings.
var scanIDPattern = regexp.MustCompile(`^sc_\d{4}-\d{2}-\d{2}_\d{6}_[0-9A-Za-z]{6}$`)

// runScanCmd returns the process exit status as a NAMED result so the deferred
// scan-log finalizer can record the real exit code in scan.log.
func runScanCmd(ctx context.Context, args []string) (exitCode int) {
	// scanStart anchors the wall-clock duration recorded in scan_runs. It is
	// captured before argument parsing so the reported duration covers the whole
	// command, not just the pipeline phases.
	scanStart := time.Now()
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	outputDir := parseStringFlag(remaining, "output-dir")
	remaining = removeFlag(remaining, "output-dir")
	excludeDirs, _ := parseExcludeFlag(remaining)
	remaining = removeFlag(remaining, "exclude")
	failOn := parseStringFlag(remaining, "fail-on")
	remaining = removeFlag(remaining, "fail-on")
	if failOn != "" && failOn != "confirmed" {
		WriteErrorJSON(fmt.Sprintf("invalid --fail-on %q (supported values: confirmed)", failOn))
		return 1
	}
	baselineScanID := parseStringFlag(remaining, "baseline")
	remaining = removeFlag(remaining, "baseline")
	timeoutSec := parseIntFlag(remaining, "timeout")
	remaining = removeFlag(remaining, "timeout")
	boundaryMode := parseStringFlag(remaining, "boundary-auto-dismiss")
	remaining = removeFlag(remaining, "boundary-auto-dismiss")
	switch boundaryMode {
	case "", "off", "external", "all":
	default:
		WriteErrorJSON(fmt.Sprintf("invalid --boundary-auto-dismiss %q (expected off|external|all)", boundaryMode))
		return 1
	}
	config.SetBoundaryAutoDismissOverride(boundaryMode)
	compileCommands := parseStringFlag(remaining, "compile-commands")
	remaining = removeFlag(remaining, "compile-commands")
	if skipped := parseStringFlag(remaining, "skip-detectors"); skipped != "" {
		config.SetSkipDetectorsOverride(skipped)
	}
	remaining = removeFlag(remaining, "skip-detectors")
	if len(remaining) == 0 {
		remaining = []string{"."}
	}
	targetPath := remaining[0]
	// The [type-filter] positional argument was historically declared in the
	// usage text but never consumed, so `scan <path> <type>` silently ran every
	// type (the most expensive memory-failure footgun on large repos). Consume
	// it now: remaining[1:] is a single type, a comma list, or "all".
	if len(remaining) > 1 {
		config.SetTypeFilterOverride(strings.Join(remaining[1:], ","))
	} else {
		// Clear any prior in-process override so a repeated invocation cannot
		// inherit another command's allow-list.
		config.SetTypeFilterOverride("")
	}
	// Validate the filter BEFORE the index/graph/detector phases. A typo or an
	// all-disabled filter must fail immediately instead of paying a full scan and
	// then reporting a silent zero-type "complete" run.
	if requested := config.TypeFilterRequested(); len(requested) > 0 {
		var unknown []string
		for _, name := range requested {
			if _, err := planner.GetVulnTypeSpec(name); err != nil {
				unknown = append(unknown, name)
			}
		}
		if len(unknown) > 0 {
			WriteErrorJSON(fmt.Sprintf("unknown type-filter type(s): %s (run `secguard types` for the registered list)", strings.Join(unknown, ", ")))
			return 1
		}
		if len(planner.TypeFilteredActiveVulnTypes(config.Load().DisabledTypeSet(), config.Load().TypeFilterSet())) == 0 {
			WriteErrorJSON("type-filter matched no enabled vulnerability type: every requested type is disabled by [disabled_types]")
			return 1
		}
	}

	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("invalid path: %v", err))
		return 1
	}
	if _, err := os.Stat(absPath); err != nil {
		WriteErrorJSON(fmt.Sprintf("target path does not exist: %v", err))
		return 1
	}

	// GAP-03: resolve compile_commands.json (flag > config > auto-detect). A
	// parse failure Warn-degrades (half-usable beats unusable) and continues the
	// scan with the zero-config constant environment.
	resolveAndLoadCompileCommands(absPath, compileCommands, defaultLogger())

	// .codeagent lives at the PROJECT ROOT — the directory the scan was launched
	// from (cwd) — never under the scan target. Auditing a subdir like `./src`
	// must still write .codeagent to the project root, so index + plan + report
	// all agree on one DB/scan location regardless of the target path.
	projectRoot, err := os.Getwd()
	if err != nil || projectRoot == "" {
		projectRoot = absPath
	}

	// Without an explicit --db, the database belongs under the project root's
	// .codeagent dir (sibling of the scan output), never as a stray sgre.db in
	// the source tree.
	dbPath = resolveDBPath(dbExplicit, dbPath, projectRoot)
	// The scans root follows the database (issue #264 #14): artifacts land
	// next to the DB they belong to, so an explicit --db relocates them with
	// the DB instead of leaving them in the launching cwd. For the canonical
	// layout this is exactly the old ScansRoot(projectRoot).
	scansRoot := report.ScansRootFromDBPath(dbPath)

	var scanID string
	var scanDir string
	if outputDir != "" {
		scanID = filepath.Base(outputDir)
		if !scanIDPattern.MatchString(scanID) {
			WriteErrorJSON(fmt.Sprintf("invalid --output-dir: basename %q does not match scan_id format sc_YYYY-MM-DD_HHMMSS_xxxxxx. Omit --output-dir to let secguard generate it, or pass a directory whose basename matches the format.", scanID))
			return 1
		}
		scanDir = outputDir
	} else {
		so := report.NewScanOutputIn(scansRoot, projectRoot)
		scanID = so.ScanID
		scanDir = so.ScanDir
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to create db directory: %v", err))
		return 1
	}

	// The agent writes its intermediate --write-json payloads under the project's
	// .sgre/.tmp (a runtime artifact, never os.TempDir). We NO LONGER wipe .tmp
	// at scan start: a previous scan that crashed mid-AI-stage (OOM, SIGKILL)
	// may have left settlement payloads the operator wants to inspect or replay,
	// and wiping them on every retry (issue #238 §3.3) silently destroyed the
	// only evidence of how far the AI got. The directory is created if absent so
	// the agent always finds a writable target; stale accumulation is bounded by
	// the operator clearing .tmp between unrelated scan campaigns.
	agentTmpDir := filepath.Join(filepath.Dir(dbPath), ".tmp")
	_ = os.MkdirAll(agentTmpDir, 0755)

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	// The stale sweep first collects the interrupted scan IDs, writes a .failed
	// marker into each leftover scan directory (an OOM-killed process never runs
	// its own failure finalizer, so without this the directory is an unmarked
	// remnant the user cannot tell apart from a successful scan), then flips the
	// rows. The scans root is the canonical location (derived from the DB,
	// issue #264 #14), not the parent of an explicit --output-dir.
	if staleIDs, err := store.StaleRunningScanIDs(ctx, scanID); err != nil {
		defaultLogger().Warn("list stale running scans failed", "error", err)
	} else {
		for _, id := range staleIDs {
			markScanDirFailed(scansRoot, id)
		}
	}
	if n, err := store.MarkStaleRunningAsFailed(ctx, scanID); err != nil {
		defaultLogger().Warn("mark stale running scans as failed", "error", err)
	} else if n > 0 {
		defaultLogger().Info("marked stale running scans as failed", "count", n)
	}
	// Create the lifecycle row before any expensive work: if this process is
	// OOM-killed, the row stays 'running' and the next scan's stale sweep marks
	// it failed. An absent row would make the interrupted scan invisible.
	if err := store.BeginScanRun(ctx, scanID); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to begin scan run: %v", err))
		return 1
	}

	logger, logCloser := newScanLogger(scanDir)
	defer func() {
		if logCloser == nil {
			return
		}
		// Terminate the log with the REAL exit status. The last INFO used to be a
		// per-type plan timing, so the log had no scan-end boundary and a run that
		// failed (or was stopped by the --fail-on CI gate) looked identical to a
		// clean one when read back. The named result carries the status here.
		logger.Info("scan finished", "scan_id", scanID, "exit_code", exitCode)
		if cerr := logCloser.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close scan log: %v\n", cerr)
		}
		logCloser = nil
	}()

	// scanFinalState is committed by the defer. It starts 'failed' so any early
	// return (including a panic unwinding through it) leaves an honest record;
	// the success path sets the computed complete/incomplete state just before
	// returning.
	scanFinalState := "failed"
	defer func() {
		// Any failed run leaves a `.failed` marker, not only a panic or an
		// OOM-killed process (issue #253 P0-4): a normal error return used to
		// leave a directory that looked like a success. Never overwrite a more
		// precise marker the panic path already wrote.
		if scanFinalState == "failed" {
			marker := filepath.Join(scanDir, ".failed")
			if _, statErr := os.Stat(marker); os.IsNotExist(statErr) {
				writeFailedMarker(scanDir, scanID, "scan failed before completion; see scan.log and scan_runs.completion_state")
			}
		}
		// The scan context may already be canceled by --timeout or Ctrl-C;
		// recording the failure must not be skipped because of that. Without
		// WithoutCancel the row would stay 'running' until the next scan's
		// stale sweep, which is exactly the window we are trying to close.
		if err := store.SetScanRunCompletionState(context.WithoutCancel(ctx), scanID, scanFinalState); err != nil {
			logger.Warn("set scan completion state failed", "state", scanFinalState, "error", err)
		}
	}()

	// A panic (e.g. a nil-deref in a detector, an unexpected filter state) used
	// to unwind straight through the log closer without leaving a trace in
	// scan.log — the last line was some plan timing and the operator had no
	// "crash" marker. Recover here, write a FATAL line to scan.log and stderr,
	// and set exitCode=1 so the named return carries the failure through the
	// log/completion defers. A Go runtime `fatal error: out of memory` is NOT
	// recoverable (the runtime aborts before defers run), so this is for panics
	// only; the OOM path is handled by the P0 callChain/chainRootName fixes.
	defer func() {
		if r := recover(); r != nil {
			logger.Error("scan panicked", "scan_id", scanID, "panic", r)
			fmt.Fprintf(os.Stderr, "FATAL: scan %s panicked: %v\n", scanID, r)
			// Mark the directory NOW (issue #253 P0-4): a recoverable crash must
			// not wait for the next scan's stale sweep to become visible. The
			// completion-state defer backfills duration_ms on the same path.
			writeFailedMarker(scanDir, scanID, fmt.Sprintf("crash (panic: %v)", r))
			exitCode = 1
		}
	}()

	sup, err := loadSuppressions(ctx, store)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to load suppressions: %v", err))
		return 1
	}
	var baseline *baselineIndex
	if baselineScanID != "" {
		baseline, err = loadBaseline(ctx, store, baselineScanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to load baseline: %v", err))
			return 1
		}
		logger.Info("baseline diff enabled", "baseline_scan_id", baselineScanID, "baseline_findings", baseline.count)
	}
	if sup.suppressedCount() > 0 {
		logger.Info("suppression index loaded", "dismissed_findings", sup.suppressedCount())
	}

	// Emit an explicit lifecycle entry so the scan log is never empty even when
	// no detector emits a Warn/Info line (e.g. after the CFG-degenerate warnings
	// were demoted to Debug). This also gives the log a stable first record.
	logger.Info("scan started", "scan_id", scanID, "target", absPath)

	outcome, err := runPipeline(ctx, store, logger, absPath, excludeDirs, config.Load().ExcludePaths())
	if err != nil {
		WriteErrorJSON(err.Error())
		return 1
	}
	indexResult := outcome.Index

	evidencePackages := []map[string]interface{}{}
	totalCandidates := 0
	totalFinalCount := 0
	totalSeedCount := 0
	totalSuppressed := 0
	totalBaselineExisting := 0
	totalAutoConfirmed := 0
	filesWithCandidates := map[string]bool{}
	var dismissedByVuln []report.VulnTypeDismissed
	totalDropped := 0
	// planErrors records any vulnerability type whose convergence step failed
	// (Planner.Plan returned an error or the plan goroutine panicked). Such a
	// type gets no scan_stats row and thus reads terminal_state "unknown" from
	// `status --per-type`; surfacing the concrete error here is what makes a
	// planner crash distinguishable from "the orchestrator never dispatched it".
	planErrors := outcome.PlanErrors
	// seedsByType records each type's RAW seed-event count (before the filter
	// chain), so a reader can tell "detector fired on nothing (seed==0)" apart
	// from "detector fired but the filters converged to zero (seed>0)". Both
	// read as "0 candidates" in candidates_by_type, and the distinction is what
	// answers "is zero candidates a detector bug or a filter over-aggressive".
	seedsByType := map[string]int{}
	// autoConfirmedByType mirrors seedsByType for the machine-confirmed tier: the
	// per-type count of findings the pipeline wrote straight to findings/ as
	// `auto-confirmed` (without a first-round AI pass). The orchestrator needs this
	// to dispatch re-review subagents for a type whose candidates converged to 0
	// but which still carries machine findings — otherwise that type skips the
	// AI second-round review entirely (the global auto_confirmed_count cannot
	// name WHICH types have them).
	autoConfirmedByType := map[string]int{}
	// degraded records a non-fatal stage failure (auto-confirm write, findings
	// read) that must still make the scan 'incomplete' rather than 'complete'.
	degraded := false

	vulnTypes := planner.TypeFilteredActiveVulnTypes(config.Load().DisabledTypeSet(), config.Load().TypeFilterSet())

	for i, vulnType := range vulnTypes {
		if errMsg, failed := planErrors[vulnType]; failed {
			evidencePackages = append(evidencePackages, map[string]interface{}{
				"vulnerability_type": vulnType,
				"error":              errMsg,
				"candidates":         []interface{}{},
			})
			continue
		}
		result := outcome.Plans[i]
		totalSeedCount += result.Summary.SeedCount
		seedsByType[vulnType] = result.Summary.SeedCount

		filterChainJSON, err := json.Marshal(result.Summary.Filters)
		if err != nil {
			filterChainJSON = []byte(`"filter_chain_marshal_failed"`)
		}

		if len(result.Summary.Dropped) > 0 {
			dismissedByVuln = append(dismissedByVuln, report.VulnTypeDismissed{
				VulnerabilityType: vulnType,
				DroppedCount:      len(result.Summary.Dropped),
				DroppedByReason:   result.Summary.DroppedByReason,
			})
			totalDropped += len(result.Summary.Dropped)
		}

		cwe := report.VulnToCWE(vulnType)
		keptCandidates, suppressedCount, baselineExisting := filterSuppressedCandidates(result.Candidates, cwe, sup, baseline)
		totalSuppressed += suppressedCount
		totalBaselineExisting += baselineExisting

		// Scope to the scan target: the incremental index keeps files from
		// earlier scans of OTHER directories, but a scan of <path> must only
		// report findings at or under <path> — not leak stale-indexed siblings.
		keptCandidates = scopeToTarget(keptCandidates, absPath)

		// Auto-confirm the pipeline-PROVED tier: a `confirmed` suspicion means a
		// flow filter or the detector proved the defect on the semantic graph, so
		// it is written straight to findings (machine verdict) and does NOT go
		// through the first-round AI classification. The agent then RE-REVIEWS
		// these in its classification loop (`report --list-auto-confirmed` +
		// `report --review-json`) and records the verdict in findings.review_status.
		// This removes the deterministic bulk (definite null, constant OOB, weak
		// crypto, sizeof-pointer, signed-compare, hardcoded secret, OOB read) from
		// the first-round AI workload, leaving only suspected/possible for initial
		// judgment.
		autoConfirmed, needsReview := splitBySuspicion(keptCandidates)
		autoWritten, autoUnwritten, autoErr := autoConfirmFindings(ctx, store, scanID, vulnType, autoConfirmed, logger)
		if autoErr != nil {
			logger.Warn("auto-confirm findings failed", "vuln_type", vulnType, "error", autoErr)
			degraded = true
		}
		// 降级回流：写失败的、以及无坐标（无法落库）的 confirmed 候选回流
		// needsReview 交由 AI 复核，绝不静默丢失（否则这批既不在 findings、也不在
		// 候选里）。
		if len(autoUnwritten) > 0 {
			needsReview = append(needsReview, autoUnwritten...)
		}
		totalAutoConfirmed += autoWritten
		autoConfirmedByType[vulnType] = autoWritten

		finalLocations := distinctFindingLocations(needsReview)
		totalFinalCount += finalLocations
		if _, err := store.InsertScanStat(ctx, &db.ScanStat{
			ScanID:      scanID,
			VulnType:    vulnType,
			SeedCount:   result.Summary.SeedCount,
			FinalCount:  finalLocations,
			FilterChain: string(filterChainJSON),
		}); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to insert scan stat for %s: %v", vulnType, err))
			return 1
		}
		// A type that converged to zero AI-review candidates has nothing for a
		// subagent to classify (any machine verdicts were already written as
		// auto-confirmed, awaiting Step 5.5 review). Mark it done here so the
		// orchestrator never has to run `report --complete-type` per empty type
		// and audit-report.md shows done instead of a misleading pending.
		if finalLocations == 0 {
			if err := store.MarkAIStageDone(ctx, scanID, vulnType); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to mark zero-candidate type %s done: %v", vulnType, err))
				return 1
			}
		}

		for _, c := range needsReview {
			if c.Target.File != "" {
				filesWithCandidates[c.Target.File] = true
			}
		}
		totalCandidates += distinctFindingLocations(needsReview)
		evidencePackages = append(evidencePackages, map[string]interface{}{
			"vulnerability_type":       vulnType,
			"cwe":                      cwe,
			"summary":                  result.Summary,
			"candidates":               needsReview,
			"suppressed_count":         suppressedCount,
			"baseline_existing":        baselineExisting,
			"original_candidate_count": len(result.Candidates),
			"auto_confirmed_count":     autoWritten,
		})
	}

	var findingsError string
	findings, err := store.ListFindingsByScanID(ctx, scanID)
	if err != nil {
		// CI gate（--fail-on）依赖 findings 计数：读失败若静默放行，confirmed/
		// suspected 会被当 0 → exit 0 放行，正是安全工具最不可接受的假阴性方向。
		if failOn != "" {
			fmt.Fprintf(os.Stderr, "error: failed to list findings for CI gate: %v\n", err)
			return 1
		}
		// A 0 count must never be mistaken for "no existing findings": surface
		// the read failure in the JSON and at Error level.
		logger.Error("list findings by scan failed", "error", err)
		findingsError = err.Error()
		degraded = true
	}
	findingsList := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		findingsList = append(findingsList, map[string]interface{}{
			"id":         f.ID,
			"rule_id":    f.RuleID,
			"severity":   f.Severity,
			"confidence": f.Confidence,
			"status":     f.Status,
		})
	}

	filesList := make([]string, 0, len(filesWithCandidates))
	for f := range filesWithCandidates {
		filesList = append(filesList, f)
	}
	sort.Strings(filesList)

	typeBreakdown := make([]report.TypeBreakdownEntry, 0, len(evidencePackages))
	for _, ep := range evidencePackages {
		vt, _ := ep["vulnerability_type"].(string)
		cands, _ := ep["candidates"].([]planner.EvidenceItem)
		count := len(cands)
		if count == 0 {
			continue
		}
		typeBreakdown = append(typeBreakdown, report.TypeBreakdownEntry{
			Type:  vt,
			CWE:   report.VulnToCWE(vt),
			Count: count,
		})
	}

	scansDir := filepath.Dir(scanDir)
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		logger.Warn("list functions failed", "error", err)
	}
	functionsInIndex := len(funcs)
	scope := scanScope(absPath, funcs)

	// Persist the incomplete ledger and derive the scan's completion state
	// before the report header is rendered, so report.md and the JSON cannot
	// claim 'complete' while a detector or plan type failed.
	incompleteCount := 0
	recordIncomplete := func(phase, reason, detail string) {
		task := &db.ScanIncompleteTask{ScanID: scanID, Phase: phase, Reason: reason, Detail: detail}
		// A canceled scan context (timeout/Ctrl-C) must still leave the ledger
		// row; otherwise the incompleteness is invisible exactly when it matters.
		if err := store.InsertIncompleteTask(context.WithoutCancel(ctx), task); err != nil {
			logger.Warn("insert incomplete task failed", "phase", phase, "error", err)
		}
		// Count it even if the ledger write failed: the in-memory error still
		// means this scan is not complete, and claiming complete would be worse.
		incompleteCount++
	}
	for _, de := range outcome.DetectorErrors {
		recordIncomplete("detector", "failed", de.Detector+": "+de.Err.Error())
	}
	for vt, msg := range planErrors {
		recordIncomplete("plan", "failed", vt+": "+msg)
	}
	// File-level read/parse failures are incomplete EVIDENCE, not a footnote:
	// every function of a skipped file is absent from every vuln type, so the
	// scan must not read complete while silently losing whole files.
	if outcome.Index != nil && outcome.Index.FilesSkipped > 0 {
		recordIncomplete("index", "files-skipped", fmt.Sprintf("%d file(s) could not be read/parsed; their functions are absent from every vuln type", outcome.Index.FilesSkipped))
	}
	if degraded {
		recordIncomplete("report", "degraded", "auto-confirm write or findings read failed")
	}
	plannedState := "complete"
	if incompleteCount > 0 {
		plannedState = "incomplete"
	}

	summaryData := report.SummaryData{
		ScanID:            scanID,
		TargetPath:        absPath,
		ScanDir:           scanDir,
		TotalCandidates:   totalCandidates,
		AutoConfirmed:     totalAutoConfirmed,
		FilesIndexed:      indexResult.FilesIndexed,
		FunctionsIndexed:  indexResult.FunctionsScanned,
		FunctionsInIndex:  functionsInIndex,
		LinesOfCode:       indexResult.LinesOfCode,
		TypeBreakdown:     typeBreakdown,
		ScanMode:          scopeMode(scope),
		EnclosingWorktree: scopeWorktree(scope),
		CompletionState:   plannedState,
		IncompleteTasks:   incompleteCount,
		ReportPath:        filepath.Join(scanDir, report.ReportFile),
		SarifPath:         filepath.Join(scanDir, report.CandidatesSarifFile),
		LatestPath:        filepath.Join(scansDir, report.LatestName),
	}
	summaryStr := report.BuildScanSummary(summaryData)

	// candidates_by_type: 摘要（每类型候选数），替代完整 evidence_packages。
	// 完整 evidence_packages 写到 report.md/SARIF，不放入 stdout——避免 398KB+ 输出
	// 触发 OpenCode 截断、污染 agent 上下文、诱导读取 tool-output 截断文件。
	// 用 distinctFindingLocations（位置去重）而不是 len(cands)（变量级）：与
	// scan_stats.final_count / status --per-type 的 candidate_count 同口径，否则
	// 汇总阶段 orchestrator 看到 scan 的变量级数和 DB 的位置级数对不上，又去拼
	// SQL 对账。
	candidatesByType := make(map[string]int, len(evidencePackages))
	for _, ep := range evidencePackages {
		vt, _ := ep["vulnerability_type"].(string)
		cands, _ := ep["candidates"].([]planner.EvidenceItem)
		candidatesByType[vt] = distinctFindingLocations(cands)
	}

	// detectorErrors surfaces any detector that failed without aborting the run.
	// It is the detector-stage twin of plan_errors: a failed detector means the
	// vuln types it feeds may read as 0 candidates WITHOUT being a genuine
	// absence, so it must reach the orchestrator's report, not just scan.log.
	detectorErrors := map[string]string{}
	for _, de := range outcome.DetectorErrors {
		detectorErrors[de.Detector] = de.Err.Error()
	}

	output := map[string]interface{}{
		"scan_id":                scanID,
		"completion_state":       plannedState,
		"incomplete_task_count":  incompleteCount,
		"candidates_by_type":     candidatesByType,
		"auto_confirmed_by_type": autoConfirmedByType,
		"seeds_by_type":          seedsByType,
		"plan_errors":            planErrors,
		"detector_errors":        detectorErrors,
		"disabled_types":         disabledTypeNames(outcome.DisabledTypes),
		"detectors_skipped":      skippedDetectorNames(outcome.SkippedDetectors), "total_candidates": totalCandidates,
		"auto_confirmed_count":    totalAutoConfirmed,
		"suppressed_count":        totalSuppressed,
		"baseline_existing_count": totalBaselineExisting,
		// 只放计数，不放整表——files_with_candidates（数百文件路径）与
		// existing_findings（整表 findings）会把主上下文一次撑爆；绝对路径从
		// 候选文件的 ## Location 块取即可。
		"files_with_candidates_count": len(filesList),
		"existing_findings_count":     len(findingsList),
		"index_summary": map[string]interface{}{
			"files_indexed":      indexResult.FilesIndexed,
			"functions_indexed":  indexResult.FunctionsScanned,
			"functions_in_index": functionsInIndex,
			"files_skipped":      indexResult.FilesSkipped,
			// Scale figures for the report header / console summary. The same
			// numbers reach report.md via ScanOverview, so "how big was this
			// scan" is answered identically wherever it is read.
			"lines_of_code": indexResult.LinesOfCode,
		},
		"scan_scope":        scope,
		"target_path":       absPath,
		"scan_dir":          scanDir,
		"candidates_sarif":  filepath.Join(scanDir, report.CandidatesSarifFile),
		"result_sarif_note": fmt.Sprintf("%s is written by `report --audit` after classification; the scan writes %s (unclassified leads at level \"note\")", report.SarifFile, report.CandidatesSarifFile),
		"_summary":          summaryStr,
	}
	if findingsError != "" {
		output["findings_error"] = findingsError
	}
	if requested := config.TypeFilterRequested(); len(requested) > 0 {
		// Make the narrowed scope recoverable from the artifact: a filtered scan
		// that silently omits types is indistinguishable from a clean full scan.
		output["type_filter"] = requested
		output["applied_types"] = vulnTypes
	}

	planResults := make([]*planner.PlanResult, 0, len(evidencePackages))
	for _, ep := range evidencePackages {
		vt, _ := ep["vulnerability_type"].(string)
		cands, _ := ep["candidates"].([]planner.EvidenceItem)
		planResults = append(planResults, &planner.PlanResult{
			VulnerabilityType: vt,
			Candidates:        cands,
		})
	}

	scanOutput := &report.ScanOutput{
		RootDir:             projectRoot,
		ScanDir:             scanDir,
		SarifPath:           filepath.Join(scanDir, report.SarifFile),
		CandidatesSarifPath: filepath.Join(scanDir, report.CandidatesSarifFile),
		ReportPath:          filepath.Join(scanDir, report.ReportFile),
		ScanID:              scanID,
		ScanMode:            scopeMode(scope),
	}
	reportStart := time.Now()
	if err := scanOutput.Write(planResults, report.IndexSummary{
		FilesIndexed:        indexResult.FilesIndexed,
		FunctionsIndexed:    indexResult.FunctionsScanned,
		FunctionsInIndex:    functionsInIndex,
		FilesSkipped:        indexResult.FilesSkipped,
		LinesOfCode:         indexResult.LinesOfCode,
		TargetPath:          absPath,
		SeedCount:           totalSeedCount,
		AutoConfirmed:       totalAutoConfirmed,
		AutoConfirmedByType: autoConfirmedByType,
		StartedAt:           scanStart,
		DurationMs:          time.Since(scanStart).Milliseconds(),
		TypesScanned:        len(evidencePackages),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write output: %v\n", err)
		output["report_error"] = fmt.Sprintf("failed to write report: %v", err)
		// 先输出 JSON（含 report_error）让调用方知道扫描完成但落盘失败，
		// 然后返回非 0 退出码强制暴露失败——不再静默返回 0。
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonBytes))
		return 1
	} else {
		// 强制落盘验证：Write() 返回 nil 不代表文件实际存在（磁盘满、NFS 延迟、
		// 权限问题在写入过程中发生等）。逐个检查输出契约文件存在且非空，
		// 任一缺失则视为致命错误——不再静默返回 0 让 agent 误读"成功"。
		// Verify what the SCAN is contracted to produce. result.sarif is not in
		// that list: it is the verdict-stage artifact and does not exist until
		// the AI classification is persisted via `report --audit`.
		var reportBytes int64
		for _, f := range []string{scanOutput.ReportPath, scanOutput.CandidatesSarifPath} {
			info, statErr := os.Stat(f)
			if statErr != nil {
				output["report_error"] = fmt.Sprintf("output file not persisted: %s: %v", f, statErr)
				fmt.Fprintf(os.Stderr, "FATAL: %s\n", output["report_error"])
				jsonBytes, _ := json.MarshalIndent(output, "", "  ")
				fmt.Fprintln(os.Stdout, string(jsonBytes))
				return 1
			}
			if info.Size() == 0 {
				output["report_error"] = fmt.Sprintf("output file is empty: %s", f)
				fmt.Fprintf(os.Stderr, "FATAL: %s\n", output["report_error"])
				jsonBytes, _ := json.MarshalIndent(output, "", "  ")
				fmt.Fprintln(os.Stdout, string(jsonBytes))
				return 1
			}
			reportBytes += info.Size()
		}
		scansDir := filepath.Dir(scanOutput.ScanDir)
		if serr := report.UpdateLatest(scansDir, scanOutput.ScanID); serr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update latest symlink: %v\n", serr)
		}

		// evidenceBytes is the candidates/ tree the AI classifier reads (per-type
		// _index.md + per-candidate evidence files). It is summed AFTER Write so
		// it reflects what actually landed on disk, not an in-memory estimate.
		// Walking a few hundred small files is microseconds — never on the
		// index/graph/detect/plan hot path, so it cannot move the scan E2E time.
		evidenceBytes := dirTreeBytes(filepath.Join(scanDir, report.CandidatesDir))

		run := &db.ScanRun{
			ScanID:           scanID,
			SourceRevision:   resolveSourceRevision(projectRoot),
			DurationMs:       time.Since(scanStart).Milliseconds(),
			IndexMs:          outcome.Timings.IndexMs,
			GraphMs:          outcome.Timings.GraphMs,
			DetectorsMs:      outcome.Timings.DetectorsMs,
			PlanMs:           outcome.Timings.PlanMs,
			ReportMs:         time.Since(reportStart).Milliseconds(),
			FilesIndexed:     indexResult.FilesIndexed,
			FunctionsIndexed: indexResult.FunctionsScanned,
			SeedCount:        totalSeedCount,
			FinalCount:       totalFinalCount,
			ReportBytes:      reportBytes,
			EvidenceBytes:    evidenceBytes,
			CompletionState:  plannedState,
			ScanMode:         scopeMode(scope),
		}
		if err := store.UpsertScanRun(ctx, run); err != nil {
			logger.Warn("insert scan run metrics failed", "error", err)
			output["scan_runs_error"] = err.Error()
		}
		output["scan_metrics"] = renderScanMetrics(run)
	}

	// 先写完 report.md/SARIF 再输出 JSON，确保调用方拿到 JSON 时 report.md 一定存在
	// （或 JSON 中含 report_error 字段）。原先 JSON 在 Write 之前输出，若 Write 失败
	// 调用方仍认为扫描成功，但 report.md 不存在，导致 agent 读取报错 File not found。
	if err := report.WriteDismissed(scanDir, report.DismissedSummary{
		ScanID:       scanID,
		TotalDropped: totalDropped,
		ByVulnType:   dismissedByVuln,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write dismissed ledger: %v\n", err)
		output["dismissed_ledger_error"] = err.Error()
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to marshal scan output: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stdout, string(jsonBytes))

	report.PrintScanSummary(os.Stderr, summaryData)

	scanFinalState = plannedState

	if failOn != "" {
		confirmedCount := 0
		for _, f := range findings {
			if f.EffectiveStatus() == "confirmed" {
				confirmedCount++
			}
		}
		if failOn == "confirmed" && confirmedCount > 0 {
			fmt.Fprintf(os.Stderr, "\nCI gate: %d confirmed finding(s) — exiting with code 2\n", confirmedCount)
			return 2
		}
	}

	return 0
}

// disabledTypeNames renders the applied type-switch list for the scan JSON
// envelope: an empty slice (not nil) so the field reads `[]` rather than `null`.
func disabledTypeNames(names []string) []string {
	if names == nil {
		return []string{}
	}
	return names
}

// skippedDetectorNames renders the applied detector-switch list for the scan JSON
// envelope, with the same empty-slice-not-null rule as disabledTypeNames.
func skippedDetectorNames(names []string) []string {
	if names == nil {
		return []string{}
	}
	return names
}

// distinctFindingLocations counts the distinct (file, line, variable) locations
// among candidates. `report --write-json` UPSERTs findings keyed on
// (scan_id, rule_id, file, line, variable), so only candidates at the SAME
// location AND SAME variable collapse into ONE finding; two different variables
// on one line (e.g. two resource variables) are two findings. final_count must
// use this location count — not the variable-level candidate count — otherwise
// `status --per-type` and `report --audit` see a phantom "written < candidate"
// gap and the orchestrator re-dispatches or raw-queries the schema in a loop.
func distinctFindingLocations(items []planner.EvidenceItem) int {
	seen := make(map[string]struct{}, len(items))
	for _, c := range items {
		key := c.Target.File + "\x00" + strconv.Itoa(c.Target.Line) + "\x00" + c.Target.Variable
		seen[key] = struct{}{}
	}
	return len(seen)
}

// splitBySuspicion partitions converged candidates into the pipeline-PROVED tier
// (suspicion "confirmed" AND no macro context) and the tier that still needs AI
// judgment (suspected / possible, plus any macro-context candidate). Only the
// former is auto-confirmed: a macro-context candidate's verdict depends on macro
// semantics the deterministic pipeline may have mis-modeled (a guard macro whose
// definition lives outside the scan, an iterator/accessor macro, a free wrapper),
// so it is handed to the AI even when the flow proof reads "confirmed".
func splitBySuspicion(candidates []planner.EvidenceItem) (confirmed, needsReview []planner.EvidenceItem) {
	for _, c := range candidates {
		if c.SuspicionLevel == "confirmed" && !c.MacroContext {
			confirmed = append(confirmed, c)
		} else {
			needsReview = append(needsReview, c)
		}
	}
	return confirmed, needsReview
}

// autoConfirmFindings writes pipeline-proved candidates straight to the findings
// table as `auto-confirmed` (machine verdict). The agent then re-reviews these in
// its classification loop (`report --list-auto-confirmed` + `report --review-json`)
// and records the verdict in findings.review_status. Each finding carries the
// pipeline's own evidence as summary/reasoning and a paste-ready fix, so a
// reviewer sees why the machine confirmed it. It returns the number written and
// the unwritten remainder (from the failing candidate onward); a write error
// aborts the batch (silent false-negatives are not acceptable here), so the
// caller can fall the remainder back to AI review.
func autoConfirmFindings(ctx context.Context, store db.Store, scanID, vulnType string, candidates []planner.EvidenceItem, logger *log.Logger) (written int, unwritten []planner.EvidenceItem, err error) {
	var pending []*db.Finding
	for _, c := range candidates {
		cwe := report.VulnToCWEForCategory(vulnType, c.Category)
		if c.Target.File == "" || c.Target.Line <= 0 {
			// A candidate with no location cannot be written to findings (the
			// upsert is keyed on file/line/function). Silently dropping it would
			// evaporate a pipeline-proved defect, so re-flow it to AI review and
			// leave a trace instead.
			if logger != nil {
				logger.Warn("auto-confirm skipped: candidate has no location", "vuln_type", vulnType, "function", c.Target.Function)
			}
			unwritten = append(unwritten, c)
			continue
		}
		var details []string
		var evidenceLines []string
		for _, e := range c.Evidence {
			d := strings.TrimSpace(e.Detail)
			if d == "" {
				continue
			}
			details = append(details, d)
			// Render the pipeline evidence as the same bullet form the
			// candidate file uses, so the finding's Evidence section (and the
			// SARIF evidence property) is self-contained even though an
			// auto-confirmed finding has no candidate file.
			label := e.Role
			if label == "" {
				label = e.Type
			}
			evidenceLines = append(evidenceLines, fmt.Sprintf("- **%s:** %s", label, d))
		}
		summary := strings.Join(details, "; ")
		if summary == "" {
			summary = fmt.Sprintf("%s in %s at line %d", vulnType, c.Target.Function, c.Target.Line)
		}
		properties, perr := buildAutoConfirmProperties(c)
		if perr != nil {
			if logger != nil {
				logger.Warn("auto-confirm properties build failed", "error", perr, "vuln_type", vulnType, "function", c.Target.Function)
			}
		}
		f := &db.Finding{
			RuleID:       cwe,
			VulnType:     vulnType,
			Severity:     planner.SeverityFor(vulnType, c.Category),
			Confidence:   1.0,
			Status:       db.StatusAutoConfirmed,
			FilePath:     c.Target.File,
			LineNumber:   c.Target.Line,
			FunctionName: c.Target.Function,
			Variable:     c.Target.Variable,
			Properties:   properties,
			Summary:      summary,
			Reasoning:    "Pipeline-proved (auto-confirmed): " + summary,
			Evidence:     strings.Join(evidenceLines, "\n"),
			FixStrategy:  report.FixSuggestion(vulnType, cwe, c),
			ScanID:       scanID,
			Fingerprint:  computeFingerprint(cwe, c.Target.File, c.Target.Function, c.Target.Line),
		}
		// An auto-confirmed finding is a machine verdict, not an open lead. Its
		// `status='auto-confirmed'` is the first-pass verdict; `review_status` is
		// deliberately LEFT NULL so it stays in the re-review selection set
		// (`report --list-auto-confirmed`, `status --per-type` unreviewed, and
		// `report --audit`'s unreviewed_auto_confirmed completeness gate) until
		// Step 5.5 (the bounded machine-verdict verification pass) writes
		// `review_status='confirmed'|'dismissed'` via `--review-json`. Marking it
		// reviewed here would make every re-review listing return 0 — the machine
		// proof is only as good as its premise (production measured a 75% FP rate
		// on the uninit tier), so a machine verdict must NOT self-mark reviewed.
		f.ReviewStatus = ""
		f.ReviewReasoning = ""
		pending = append(pending, f)
	}
	// One immediate transaction for the whole auto-confirm set: the old
	// per-finding autocommit paid one BEGIN/COMMIT + WAL record + write-lock
	// round-trip per row, which dominated the scan tail on repos with tens of
	// thousands of machine-proved candidates. A mid-batch failure rolls back
	// everything and returns the FULL candidate list for AI review (the
	// per-row error already carries its location).
	if err := store.WithImmediateTx(ctx, func(tx db.Store) error {
		for _, f := range pending {
			if _, err := tx.UpsertFinding(ctx, f); err != nil {
				return fmt.Errorf("upsert auto-confirmed %s:%d: %w", f.FilePath, f.LineNumber, err)
			}
		}
		return nil
	}); err != nil {
		return 0, append(unwritten, candidates...), err
	}
	written = len(pending)
	return written, unwritten, nil
}

func resolveSourceRevision(projectRoot string) string {
	if !git.IsRepo(projectRoot) {
		return ""
	}
	sha, err := git.RevParse(projectRoot, "HEAD")
	if err != nil {
		return ""
	}
	return sha
}

// buildAutoConfirmProperties serializes what the re-review (`report
// --list-auto-confirmed`) needs to judge the machine verdict WITHOUT a source
// read: the evidence fragments (the narrative) plus the hint tokens and
// verdict facts (the distilled basis, Evidence Contract v2). The re-review
// reads the same facts the initial classification saw, so a "getter mistaken
// for an allocator" false positive is visible at a glance.
func buildAutoConfirmProperties(c planner.EvidenceItem) (string, error) {
	evBytes, err := json.Marshal(c.Evidence)
	if err != nil {
		return "", fmt.Errorf("marshal auto_confirm_evidence: %w", err)
	}
	base := map[string]json.RawMessage{"auto_confirm_evidence": evBytes}
	if len(c.HintTokens) > 0 {
		htBytes, err := json.Marshal(c.HintTokens)
		if err != nil {
			return "", fmt.Errorf("marshal auto_confirm_hint_tokens: %w", err)
		}
		base["auto_confirm_hint_tokens"] = htBytes
	}
	if len(c.VerdictFacts) > 0 {
		vfBytes, err := json.Marshal(c.VerdictFacts)
		if err != nil {
			return "", fmt.Errorf("marshal auto_confirm_verdict_facts: %w", err)
		}
		base["auto_confirm_verdict_facts"] = vfBytes
	}
	out, err := json.Marshal(base)
	if err != nil {
		return "", fmt.Errorf("marshal properties: %w", err)
	}
	return string(out), nil
}

func newScanLogger(scanDir string) (*log.Logger, io.Closer) {
	if scanDir == "" {
		return log.Default(), nopCloser{}
	}
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot create scan log dir: %v\n", err)
		return log.Default(), nopCloser{}
	}
	logPath := filepath.Join(scanDir, report.ScanLogFile)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot create scan log file: %v\n", err)
		return log.Default(), nopCloser{}
	}
	// 全量 INFO 只进 scan.log（避免刷屏污染 agent 上下文）；WARN/ERROR 仍回显 stderr。
	logger, closer := log.NewSplit(os.Stderr, f, log.LevelWarn, log.LevelInfo)
	// A Go runtime fatal error (stack overflow, out of memory) bypasses the
	// logger and writes to stderr only, so the stale sweep could never classify
	// a crash from scan.log (issue #253 P0-4). `debug.SetCrashOutput` duplicates
	// f's descriptor and mirrors the fatal output into scan.log. A recovered
	// panic is not "unhandled", so this does not interfere with the explicit
	// panic path.
	if derr := debug.SetCrashOutput(f, debug.CrashOptions{}); derr == nil {
		return logger, &crashOutputCloser{inner: closer}
	}
	return logger, closer
}

// crashOutputCloser clears the process-global crash-output sink before closing
// the scan log, so a later panic never writes to a closed descriptor.
type crashOutputCloser struct{ inner io.Closer }

func (c *crashOutputCloser) Close() error {
	_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
	return c.inner.Close()
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// markScanDirFailed writes a .failed marker into a leftover scan directory, so
// an OOM-killed / interrupted scan is visibly distinguishable from a successful
// one (its "latest" symlink was never updated, so without the marker the
// directory looks identical to a success). A missing directory is a no-op: a
// scan that died before creating its directory has nothing to mark.
//
// The directory is resolved under the canonical scans root, which matches every
// default scan. A scan started with an explicit --output-dir lives elsewhere,
// so its leftover directory is not marked here — a documented limitation (such
// runs also typically pair --output-dir with a fresh --db, so this sweep never
// sees their scan_runs rows anyway).
func markScanDirFailed(scansRoot, scanID string) {
	scanDir := filepath.Join(scansRoot, scanID)
	if _, err := os.Stat(scanDir); err != nil {
		return
	}
	// Classify the failure instead of lumping every cause into "OOM or crash"
	// (issue #253 P0-4): a Go runtime `fatal error` (stack overflow, out of
	// memory) in the scan log means the process CRASHED; anything else means
	// the run was interrupted (SIGKILL, Ctrl-C, host reboot) and the log simply
	// stops mid-phase. `newScanLogger` mirrors runtime fatal output into
	// scan.log via debug.SetCrashOutput, so this is a real signal (the runtime
	// otherwise writes to stderr only).
	reason := "interrupted (SIGKILL/OOM-kill/Ctrl-C); the scan log ends mid-phase"
	if fileContainsAny(filepath.Join(scanDir, "scan.log"), "fatal error", "goroutine stack exceeds") {
		reason = "crash (Go runtime fatal error in scan.log)"
	}
	writeFailedMarker(scanDir, scanID, reason+"; marked by a later scan's stale sweep")
}

// writeFailedMarker writes the .failed marker with an explicit failure cause.
func writeFailedMarker(scanDir, scanID, reason string) {
	marker := filepath.Join(scanDir, ".failed")
	body := fmt.Sprintf("scan %s did not complete: %s\n", scanID, reason)
	if err := os.WriteFile(marker, []byte(body), 0644); err != nil {
		defaultLogger().Warn("write failed-scan marker failed", "path", marker, "error", err)
	}
}

// fileContainsAny reports whether the file contains one of the needles, reading
// at most the first 8 MB (a crash traceback follows the fatal line, so the
// interesting text is near the END of the crash segment, not within the last
// 40 lines). Any read failure reports false.
func fileContainsAny(path string, needles ...string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil && len(data) == 0 {
		return false
	}
	s := string(data)
	for _, n := range needles {
		if n != "" && strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// dirTreeBytes sums the size of every regular file under dir. It is used once
// per scan to record the candidate-evidence volume the AI will read; a missing
// dir returns 0 (the metric degrades, it never fails the scan).
func dirTreeBytes(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// scopeToTarget keeps only candidates whose file is at or under targetDir, so a
// scan of a subdirectory does not leak findings from files the incremental
// index still holds from earlier scans of other directories.
func scopeToTarget(items []planner.EvidenceItem, targetDir string) []planner.EvidenceItem {
	kept := make([]planner.EvidenceItem, 0, len(items))
	for _, it := range items {
		if it.Target.File == "" || isUnder(targetDir, it.Target.File) {
			kept = append(kept, it)
		}
	}
	return kept
}

// isUnder reports whether path is targetDir itself or a descendant of it.
func isUnder(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		// filepath.Rel fails when the two paths live on different volumes or mix
		// separators. Fall back to a lexical prefix check rather than dropping
		// the candidate, so an unusual path form never turns into a batch
		// false-negative.
		return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func runStatusCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, _ := parseDBFlag(args)
	// Limits are a property of the installed engine, not of a scan, so they are
	// answered without requiring an sgre.db.
	if hasFlag(args, "show-limits") {
		WriteJSON(scanLimits())
		return 0
	}
	var found bool
	dbPath, found = resolveExistingDBPath(dbExplicit, dbPath)

	if !found {
		WriteJSON(map[string]interface{}{
			"indexed": false,
			"state":   "empty",
			"message": "No sgre.db found. Run 'secguard scan <path>' to create an index.",
			"db_path": dbPath,
		})
		return 0
	}

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	claimType := parseStringFlag(args, "claim-type")
	claimRange := parseStringFlag(args, "claim-range")
	claimHolder := parseStringFlag(args, "claim-holder")
	if claimType != "" || claimRange != "" || claimHolder != "" {
		if claimType == "" || claimRange == "" || claimHolder == "" {
			WriteErrorJSON("--claim-type, --claim-range and --claim-holder must be passed together")
			return 1
		}
		if planner.CWEForType(claimType) == "" {
			WriteErrorJSON(fmt.Sprintf("unknown vulnerability type %q; run 'secguard types' for the authoritative list", claimType))
			return 1
		}
		scanID := parseStringFlag(args, "scan-id")
		if scanID == "" {
			latest, lerr := store.GetLatestScanID(ctx)
			if lerr != nil {
				WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", lerr))
				return 1
			}
			scanID = latest
		}
		if scanID == "" {
			WriteErrorJSON("no scan found; run 'secguard scan <path>' first or pass --scan-id")
			return 1
		}
		staleBefore := time.Now().Add(-settlementClaimTTL).UnixMilli()
		claim, cerr := store.ClaimSettlementRange(ctx, scanID, claimType, normalizeSettlementRange(claimRange), claimHolder, staleBefore, hasFlag(args, "reclaim"))
		if cerr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to claim settlement range: %v", cerr))
			return 1
		}
		WriteJSON(claim)
		return 0
	}

	if hasFlag(args, "release-claim") || hasFlag(args, "fail-claim") {
		if claimType == "" || claimRange == "" || claimHolder == "" {
			WriteErrorJSON("--release-claim/--fail-claim require --claim-type, --claim-range and --claim-holder")
			return 1
		}
		scanID := parseStringFlag(args, "scan-id")
		if scanID == "" {
			latest, lerr := store.GetLatestScanID(ctx)
			if lerr != nil {
				WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", lerr))
				return 1
			}
			scanID = latest
		}
		if scanID == "" {
			WriteErrorJSON("no scan found; run 'secguard scan <path>' first or pass --scan-id")
			return 1
		}
		status := "released"
		if hasFlag(args, "fail-claim") {
			status = "failed"
		}
		ok, rerr := store.ReleaseSettlementClaim(ctx, scanID, claimType, normalizeSettlementRange(claimRange), claimHolder, status)
		if rerr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to release claim: %v", rerr))
			return 1
		}
		WriteJSON(map[string]interface{}{
			"scan_id":    scanID,
			"vuln_type":  claimType,
			"range":      normalizeSettlementRange(claimRange),
			"holder":     claimHolder,
			"released":   ok,
			"new_status": status,
			"note":       "released=false means the row was not this holder's live claim (already settled, released, or taken over) — no state was changed",
		})
		return 0
	}

	if hasFlag(args, "reports") {
		res := listSubagentReports(dbPath, parseStringFlag(args, "scan-id"))
		if err := persistSettlementReports(ctx, store, res); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to persist settlement reports: %v", err))
			return 1
		}
		// Attach the classified/total heartbeat so the orchestrator reads a
		// machine progress signal instead of inferring liveness from file mtime.
		totalsByScan := map[string]map[string]int{}
		for _, rep := range res.Reports {
			if rep.ScanID == "" {
				continue
			}
			if _, ok := totalsByScan[rep.ScanID]; ok {
				continue
			}
			totals := map[string]int{}
			if stats, serr := store.ListScanStats(ctx, rep.ScanID); serr == nil {
				for _, st := range stats {
					totals[st.VulnType] = st.FinalCount
				}
			}
			totalsByScan[rep.ScanID] = totals
		}
		enrichReportProgress(&res, totalsByScan)
		WriteJSON(res)
		return 0
	}

	if hasFlag(args, "per-type") {
		scanID := parseStringFlag(args, "scan-id")
		if scanID == "" {
			latest, lerr := store.GetLatestScanID(ctx)
			if lerr != nil {
				WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", lerr))
				return 1
			}
			scanID = latest
		}
		if scanID == "" {
			WriteErrorJSON("no scan found; run 'secguard scan <path>' first or pass --scan-id")
			return 1
		}
		statuses, perr := store.ListPerTypeStatus(ctx, scanID, planner.CWEsForType)
		if perr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to list per-type status: %v", perr))
			return 1
		}
		seen := make(map[string]bool, len(statuses))
		for _, st := range statuses {
			seen[st.VulnType] = true
		}
		// A disabled type (type switch) is intentionally absent from scan_stats —
		// it must NOT be appended as "unknown" (that would read as a failed type
		// and trigger a false resume/re-dispatch). The active set is the SAME
		// one the scan used (disabled AND --type-filter), or a filtered scan's
		// unselected types would show up as unknown/missing-type.
		for _, vt := range planner.TypeFilteredActiveVulnTypes(config.Load().DisabledTypeSet(), config.Load().TypeFilterSet()) {
			if !seen[vt] {
				statuses = append(statuses, &db.PerTypeStatus{
					VulnType:       vt,
					CWE:            planner.CWEForType(vt),
					CandidateCount: 0,
					WrittenCount:   0,
					TerminalState:  "unknown",
				})
			}
		}
		// The scans root follows the resolved DB (ScansRootFromDBPath): for the
		// canonical layout that is the launching cwd's .codeagent tree, and for
		// an explicit --db it is the tree the DB lives in — the same rule the
		// scan command writes artifacts under (issue #264 #14), so index_shards
		// (issue #264 #9/#20) resolves against the artifacts of THIS database.
		enriched, err := enrichPerTypeStatusFromRoot(ctx, store, scanID, statuses, report.ScansRootFromDBPath(dbPath))
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to enrich per-type status: %v", err))
			return 1
		}
		WriteJSON(enriched)
		return 0
	}

	files, err := store.ListFiles(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list files: %v", err))
		return 1
	}
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list functions: %v", err))
		return 1
	}

	allEvents := 0
	for _, et := range planner.AllSeedEventTypes() {
		n, err := store.CountEventsByType(ctx, et)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to count events: %v", err))
			return 1
		}
		allEvents += n
	}
	for _, et := range planner.AuxEvidenceEventTypes() {
		n, err := store.CountEventsByType(ctx, et)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to count events: %v", err))
			return 1
		}
		allEvents += n
	}

	// Scope the verdict census to ONE scan (issue #253 P2-6). findings rows are
	// UPSERTed per scan_id and never deleted, so an unscoped COUNT(*) mixes
	// every historical scan and can never reconcile with `report --audit`,
	// which reads exactly one scan. `--scan-id` selects it explicitly;
	// otherwise the latest scan is used, matching the audit's default.
	scanID := parseStringFlag(args, "scan-id")
	if scanID == "" {
		scanID, _ = store.GetLatestScanID(ctx)
	}
	scope := ""
	var scopeArgs []interface{}
	if scanID != "" {
		scope = " AND scan_id = ?"
		scopeArgs = append(scopeArgs, scanID)
	}
	countFindings := func(where string) (int, error) {
		var n int
		err := store.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM findings WHERE `+where+scope, scopeArgs...).Scan(&n)
		return n, err
	}
	findingsCount, err := countFindings("1=1")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count findings: %v", err))
		return 1
	}
	// Split the raw row count into the audit's verdict buckets, mirroring
	// db.Finding.FinalStatus(): a review dismissal (dismissed / suspected-kept /
	// false_positive) drops the row from the actionable set, and an inconclusive
	// review (needs_more_evidence) keeps its first-pass verdict. The old queries
	// only counted status='auto-confirmed' + review_status='dismissed', so a
	// status='confirmed' row later reviewed out (or !false_positive) still
	// inflated the "confirmed" total.
	var confirmedCount, autoConfirmedCount, reviewedOutCount int
	confirmedCount, err = countFindings("status = 'confirmed' AND COALESCE(review_status,'') NOT IN ('dismissed','suspected-kept','false_positive')")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count confirmed findings: %v", err))
		return 1
	}
	autoConfirmedCount, err = countFindings("status = 'auto-confirmed' AND COALESCE(review_status,'') NOT IN ('dismissed','suspected-kept','false_positive')")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count auto-confirmed findings: %v", err))
		return 1
	}
	reviewedOutCount, err = countFindings("status IN ('confirmed','auto-confirmed') AND review_status IN ('dismissed','suspected-kept','false_positive')")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to count reviewed-out findings: %v", err))
		return 1
	}

	output := map[string]interface{}{
		"indexed":                  true,
		"state":                    indexState(files, dbPath),
		"db_path":                  dbPath,
		"scan_id":                  scanID,
		"files_indexed":            len(files),
		"functions_indexed":        len(funcs),
		"security_events":          allEvents,
		"findings_count":           findingsCount,
		"confirmed_findings_count": confirmedCount,
		"auto_confirmed_count":     autoConfirmedCount,
		"reviewed_out_count":       reviewedOutCount,
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to marshal output: %v", err))
		return 1
	}
	fmt.Fprintln(os.Stdout, string(jsonBytes))
	return 0
}

// indexState reports the index's freshness: empty (no files), stale (any indexed
// source file is newer than the DB), or ready. It early-exits on the first stale
// file so a large codebase does not stat every source on every `secguard status`.
func indexState(files []*db.File, dbPath string) string {
	if len(files) == 0 {
		return "empty"
	}
	if dbPath == "" {
		return "ready"
	}
	dbInfo, err := os.Stat(dbPath)
	if err != nil {
		return "ready"
	}
	for _, f := range files {
		info, err := os.Stat(f.Path)
		if err != nil {
			continue // deleted/moved file cannot be re-stat'd; not a stale signal
		}
		if info.ModTime().After(dbInfo.ModTime()) {
			return "stale"
		}
	}
	return "ready"
}

// resolveAndLoadCompileCommands resolves the compile_commands.json path in
// priority order (flag > config > auto-detect under the target), loads it, and
// stores it process-wide for the constant-environment builder (GAP-03). A parse
// failure Warn-degrades and continues the scan (half-usable beats unusable).
func resolveAndLoadCompileCommands(target, flagPath string, logger *log.Logger) {
	path := flagPath
	if path == "" {
		path = config.Load().Scan.CompileCommands
	}
	if path == "" {
		for _, candidate := range []string{
			filepath.Join(target, "compile_commands.json"),
			filepath.Join(target, "build", "compile_commands.json"),
		} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		return
	}
	cc, err := build.LoadCompileCommands(path)
	if err != nil {
		if logger != nil {
			logger.Warn("compile_commands load failed (continuing without -D/-I)", "path", path, "error", err)
		}
		return
	}
	build.SetCompileCommands(cc)
	if logger != nil {
		logger.Info("compile_commands loaded", "path", path, "defines", len(cc.Defines), "include_dirs", len(cc.IncludeDirs))
	}
}
