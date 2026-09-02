package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
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

func runScanCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	outputDir := parseStringFlag(remaining, "output-dir")
	remaining = removeFlag(remaining, "output-dir")
	excludeDirs, _ := parseExcludeFlag(remaining)
	remaining = removeFlag(remaining, "exclude")
	failOn := parseStringFlag(remaining, "fail-on")
	remaining = removeFlag(remaining, "fail-on")
	baselineScanID := parseStringFlag(remaining, "baseline")
	remaining = removeFlag(remaining, "baseline")
	timeoutSec := parseIntFlag(remaining, "timeout")
	remaining = removeFlag(remaining, "timeout")
	if len(remaining) == 0 {
		remaining = []string{"."}
	}
	targetPath := remaining[0]

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
		so := report.NewScanOutput(projectRoot)
		scanID = so.ScanID
		scanDir = so.ScanDir
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to create db directory: %v", err))
		return 1
	}

	// The agent writes its intermediate --write-json payloads under the project's
	// .sgre/.tmp (a runtime artifact, never os.TempDir), and we clear it at scan
	// start so stale payloads from a previous session do not accumulate. It is
	// re-created so the agent always finds a writable target.
	agentTmpDir := filepath.Join(filepath.Dir(dbPath), ".tmp")
	_ = os.RemoveAll(agentTmpDir)
	_ = os.MkdirAll(agentTmpDir, 0755)

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	logger, logCloser := newScanLogger(scanDir)
	defer func() {
		if logCloser != nil {
			_ = logCloser.Close()
		}
	}()

	sup := loadSuppressions(ctx, store)
	var baseline *baselineIndex
	if baselineScanID != "" {
		baseline = loadBaseline(ctx, store, baselineScanID)
		logger.Info("baseline diff enabled", "baseline_scan_id", baselineScanID, "baseline_findings", baseline.count)
	}
	if sup.suppressedCount() > 0 {
		logger.Info("suppression index loaded", "dismissed_findings", sup.suppressedCount())
	}

	// Emit an explicit lifecycle entry so the scan log is never empty even when
	// no detector emits a Warn/Info line (e.g. after the CFG-degenerate warnings
	// were demoted to Debug). This also gives the log a stable first record.
	logger.Info("scan started", "scan_id", scanID, "target", absPath)

	outcome, err := runPipeline(ctx, store, logger, absPath, excludeDirs)
	if err != nil {
		WriteErrorJSON(err.Error())
		return 1
	}
	indexResult := outcome.Index

	evidencePackages := []map[string]interface{}{}
	totalCandidates := 0
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

	vulnTypes := planner.AllVulnTypes()

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

		filterChainJSON, _ := json.Marshal(result.Summary.Filters)

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
		// it is written straight to findings (machine verdict) and the AI never
		// re-reviews it. This removes the deterministic bulk (definite null,
		// constant OOB, weak crypto, sizeof-pointer, signed-compare, hardcoded
		// secret, OOB read) from the AI's workload, leaving only suspected/
		// possible for actual judgment.
		autoConfirmed, needsReview := splitBySuspicion(keptCandidates)
		autoWritten, autoUnwritten, autoErr := autoConfirmFindings(ctx, store, scanID, vulnType, autoConfirmed)
		if autoErr != nil {
			logger.Warn("auto-confirm findings failed", "vuln_type", vulnType, "error", autoErr)
			// 写失败降级：未写成功的 confirmed 候选回流 needsReview 交由 AI 复核，
			// 绝不静默丢失（否则这批既不在 findings、也不在候选里）。
			needsReview = append(needsReview, autoUnwritten...)
		}
		totalAutoConfirmed += autoWritten

		if _, err := store.InsertScanStat(ctx, &db.ScanStat{
			ScanID:      scanID,
			VulnType:    vulnType,
			SeedCount:   result.Summary.SeedCount,
			FinalCount:  len(needsReview),
			FilterChain: string(filterChainJSON),
		}); err != nil {
			logger.Warn("insert scan stat failed", "vuln_type", vulnType, "error", err)
		}

		for _, c := range needsReview {
			if c.Target.File != "" {
				filesWithCandidates[c.Target.File] = true
			}
		}
		totalCandidates += len(needsReview)
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

	findings, err := store.ListFindingsByScanID(ctx, scanID)
	if err != nil {
		// CI gate（--fail-on）依赖 findings 计数：读失败若静默放行，confirmed/
		// suspected 会被当 0 → exit 0 放行，正是安全工具最不可接受的假阴性方向。
		if failOn != "" {
			fmt.Fprintf(os.Stderr, "error: failed to list findings for CI gate: %v\n", err)
			return 1
		}
		logger.Warn("list findings by scan failed", "error", err)
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
	summaryData := report.SummaryData{
		ScanID:           scanID,
		TargetPath:       absPath,
		ScanDir:          scanDir,
		TotalCandidates:  totalCandidates,
		AutoConfirmed:    totalAutoConfirmed,
		FilesIndexed:     indexResult.FilesIndexed,
		FunctionsIndexed: indexResult.FunctionsIndexed,
		FunctionsInIndex: functionsInIndex,
		TypeBreakdown:    typeBreakdown,
		ReportPath:       filepath.Join(scanDir, report.ReportFile),
		SarifPath:        filepath.Join(scanDir, report.CandidatesSarifFile),
		LatestPath:       filepath.Join(scansDir, report.LatestName),
	}
	summaryStr := report.BuildScanSummary(summaryData)

	// candidates_by_type: 摘要（每类型候选数），替代完整 evidence_packages。
	// 完整 evidence_packages 写到 report.md/SARIF，不放入 stdout——避免 398KB+ 输出
	// 触发 OpenCode 截断、污染 agent 上下文、诱导读取 tool-output 截断文件。
	candidatesByType := make(map[string]int, len(evidencePackages))
	for _, ep := range evidencePackages {
		vt, _ := ep["vulnerability_type"].(string)
		cands, _ := ep["candidates"].([]planner.EvidenceItem)
		candidatesByType[vt] = len(cands)
	}

	output := map[string]interface{}{
		"scan_id":                 scanID,
		"candidates_by_type":      candidatesByType,
		"plan_errors":             planErrors,
		"total_candidates":        totalCandidates,
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
			"functions_indexed":  indexResult.FunctionsIndexed,
			"functions_in_index": functionsInIndex,
			"files_skipped":      indexResult.FilesSkipped,
		},
		"target_path":       absPath,
		"scan_dir":          scanDir,
		"candidates_sarif":  filepath.Join(scanDir, report.CandidatesSarifFile),
		"result_sarif_note": fmt.Sprintf("%s is written by `report --audit` after classification; the scan writes %s (unclassified leads at level \"note\")", report.SarifFile, report.CandidatesSarifFile),
		"_summary":          summaryStr,
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
	}
	if err := scanOutput.Write(planResults, report.IndexSummary{
		FilesIndexed:     indexResult.FilesIndexed,
		FunctionsIndexed: indexResult.FunctionsIndexed,
		FunctionsInIndex: functionsInIndex,
		FilesSkipped:     indexResult.FilesSkipped,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write output: %v\n", err)
		output["report_error"] = fmt.Sprintf("failed to write report: %v", err)
		// 先输出 JSON（含 report_error）让调用方知道扫描完成但落盘失败，
		// 然后返回非 0 退出码强制暴露失败——不再静默返回 0。
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonBytes))
		return 1
	} else {
		if logCloser != nil {
			if cerr := logCloser.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to close scan log: %v\n", cerr)
			}
			logCloser = nil
		}
		// 强制落盘验证：Write() 返回 nil 不代表文件实际存在（磁盘满、NFS 延迟、
		// 权限问题在写入过程中发生等）。逐个检查输出契约文件存在且非空，
		// 任一缺失则视为致命错误——不再静默返回 0 让 agent 误读"成功"。
		// Verify what the SCAN is contracted to produce. result.sarif is not in
		// that list: it is the verdict-stage artifact and does not exist until
		// the AI classification is persisted via `report --audit`.
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
		}
		scansDir := filepath.Dir(scanOutput.ScanDir)
		if serr := report.UpdateLatest(scansDir, scanOutput.ScanID); serr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update latest symlink: %v\n", serr)
		}
	}

	// 先写完 report.md/SARIF 再输出 JSON，确保调用方拿到 JSON 时 report.md 一定存在
	// （或 JSON 中含 report_error 字段）。原先 JSON 在 Write 之前输出，若 Write 失败
	// 调用方仍认为扫描成功，但 report.md 不存在，导致 agent 读取报错 File not found。
	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Fprintln(os.Stdout, string(jsonBytes))

	report.PrintScanSummary(os.Stderr, summaryData)

	if err := report.WriteDismissed(scanDir, report.DismissedSummary{
		ScanID:       scanID,
		TotalDropped: totalDropped,
		ByVulnType:   dismissedByVuln,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write dismissed ledger: %v\n", err)
	}

	if failOn != "" {
		confirmedCount := 0
		suspectedCount := 0
		for _, f := range findings {
			switch f.EffectiveStatus() {
			case "confirmed":
				confirmedCount++
			case "suspected":
				suspectedCount++
			}
		}
		if failOn == "confirmed" && confirmedCount > 0 {
			fmt.Fprintf(os.Stderr, "\nCI gate: %d confirmed finding(s) — exiting with code 2\n", confirmedCount)
			return 2
		}
		if failOn == "suspected" && suspectedCount > 0 {
			fmt.Fprintf(os.Stderr, "\nCI gate: %d suspected finding(s) — exiting with code 3\n", suspectedCount)
			return 3
		}
	}

	return 0
}

// splitBySuspicion partitions converged candidates into the pipeline-PROVED tier
// (suspicion "confirmed") and the tier that still needs AI judgment (suspected /
// possible). Only the latter is handed to the AI; the former is auto-confirmed.
func splitBySuspicion(candidates []planner.EvidenceItem) (confirmed, needsReview []planner.EvidenceItem) {
	for _, c := range candidates {
		if c.SuspicionLevel == "confirmed" {
			confirmed = append(confirmed, c)
		} else {
			needsReview = append(needsReview, c)
		}
	}
	return confirmed, needsReview
}

// autoConfirmFindings writes pipeline-proved candidates straight to the findings
// table as `confirmed` (machine verdict), so the AI never re-reviews them. Each
// finding carries the pipeline's own evidence as summary/reasoning and a
// paste-ready fix, so a reviewer sees why the machine confirmed it. It returns
// the number written and the unwritten remainder (from the failing candidate
// onward); a write error aborts the batch (silent false-negatives are not
// acceptable here), so the caller can fall the remainder back to AI review.
func autoConfirmFindings(ctx context.Context, store db.Store, scanID, vulnType string, candidates []planner.EvidenceItem) (written int, unwritten []planner.EvidenceItem, err error) {
	cwe := report.VulnToCWE(vulnType)
	for i, c := range candidates {
		if c.Target.File == "" || c.Target.Line <= 0 {
			continue
		}
		var details []string
		for _, e := range c.Evidence {
			if d := strings.TrimSpace(e.Detail); d != "" {
				details = append(details, d)
			}
		}
		summary := strings.Join(details, "; ")
		if summary == "" {
			summary = fmt.Sprintf("%s in %s at line %d", vulnType, c.Target.Function, c.Target.Line)
		}
		f := &db.Finding{
			RuleID:       cwe,
			Severity:     "high",
			Confidence:   1.0,
			Status:       db.StatusAutoConfirmed,
			FilePath:     c.Target.File,
			LineNumber:   c.Target.Line,
			FunctionName: c.Target.Function,
			Summary:      summary,
			Reasoning:    "Pipeline-proved (auto-confirmed, no AI re-review): " + summary,
			FixStrategy:  report.FixSuggestion(vulnType, cwe, c),
			ScanID:       scanID,
			Fingerprint:  computeFingerprint(cwe, c.Target.File, c.Target.Function, c.Target.Line),
		}
		if _, err := store.UpsertFinding(ctx, f); err != nil {
			return written, candidates[i:], fmt.Errorf("upsert auto-confirmed %s:%d: %w", c.Target.File, c.Target.Line, err)
		}
		written++
	}
	return written, nil, nil
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
	return logger, closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

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
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func runStatusCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, _ := parseDBFlag(args)
	dbPath = resolveDBPath(dbExplicit, dbPath, ".")

	if _, err := os.Stat(dbPath); err != nil {
		WriteJSON(map[string]interface{}{
			"indexed": false,
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
		statuses, perr := store.ListPerTypeStatus(ctx, scanID, planner.CWEForType)
		if perr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to list per-type status: %v", perr))
			return 1
		}
		seen := make(map[string]bool, len(statuses))
		for _, st := range statuses {
			seen[st.VulnType] = true
		}
		for _, vt := range planner.AllVulnTypes() {
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
		WriteJSON(statuses)
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
	for _, et := range []string{"NULL_VALUE", "NULL_GUARD", "MEMORY_RELEASE", "RESOURCE_RELEASE", "VALUE_INIT"} {
		n, err := store.CountEventsByType(ctx, et)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to count events: %v", err))
			return 1
		}
		allEvents += n
	}

	findings, err := store.ListFindings(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list findings: %v", err))
		return 1
	}

	output := map[string]interface{}{
		"indexed":           true,
		"db_path":           dbPath,
		"files_indexed":     len(files),
		"functions_indexed": len(funcs),
		"security_events":   allEvents,
		"findings_count":    len(findings),
	}

	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Fprintln(os.Stdout, string(jsonBytes))
	return 0
}
