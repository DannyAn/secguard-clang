package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

func runScanCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	outputDir := parseStringFlag(remaining, "output-dir")
	remaining = removeFlag(remaining, "output-dir")
	if len(remaining) == 0 {
		remaining = []string{"."}
	}
	targetPath := remaining[0]

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("invalid path: %v", err))
		return 1
	}
	if _, err := os.Stat(absPath); err != nil {
		WriteErrorJSON(fmt.Sprintf("target path does not exist: %v", err))
		return 1
	}

	// Without an explicit --db, the database belongs under the target repo's
	// .codeagent dir (sibling of the scan output), never as a stray sgre.db in
	// the source tree.
	dbPath = resolveDBPath(dbExplicit, dbPath, absPath)

	var scanID string
	var scanDir string
	if outputDir != "" {
		scanID = filepath.Base(outputDir)
		scanDir = outputDir
	} else {
		so := report.NewScanOutput(absPath)
		scanID = so.ScanID
		scanDir = so.ScanDir
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to create db directory: %v", err))
		return 1
	}

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

	// Emit an explicit lifecycle entry so the scan log is never empty even when
	// no detector emits a Warn/Info line (e.g. after the CFG-degenerate warnings
	// were demoted to Debug). This also gives the log a stable first record.
	logger.Info("scan started", "scan_id", scanID, "target", absPath)

	p := parser.NewParser()
	defer p.CloseAll()

	idx := indexer.NewIndexer(store, logger)
	idxStart := time.Now()
	indexResult, err := idx.Index(ctx, absPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("index failed: %v", err))
		return 1
	}
	logger.Info("phase timing", "phase", "index", "elapsed_ms", time.Since(idxStart).Milliseconds())

	cgBuilder := graph.NewCallGraphBuilder(store, p, logger)
	cgStart := time.Now()
	cgBuilder.Build(ctx)
	logger.Info("phase timing", "phase", "call_graph", "elapsed_ms", time.Since(cgStart).Milliseconds())

	dfBuilder := graph.NewDataFlowBuilder(store, p, logger)
	dfStart := time.Now()
	dfBuilder.Build(ctx)
	logger.Info("phase timing", "phase", "data_flow", "elapsed_ms", time.Since(dfStart).Milliseconds())

	if err := store.ClearSecurityEvents(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to clear security events: %v", err))
		return 1
	}

	detStart := time.Now()
	evidence.RunAllDetectors(ctx, store, p, logger)
	logger.Info("phase timing", "phase", "detectors_total", "elapsed_ms", time.Since(detStart).Milliseconds())

	evidencePackages := []map[string]interface{}{}
	totalCandidates := 0
	filesWithCandidates := map[string]bool{}
	var dismissedByVuln []report.VulnTypeDismissed
	totalDropped := 0
	for _, vulnType := range planner.AllVulnTypes() {
		pl := planner.NewPlanner(store, p, logger)
		planStart := time.Now()
		result, err := pl.Plan(ctx, vulnType)
		logger.Info("phase timing", "phase", "plan_"+vulnType, "elapsed_ms", time.Since(planStart).Milliseconds())
		if err != nil {
			evidencePackages = append(evidencePackages, map[string]interface{}{
				"vulnerability_type": vulnType,
				"error":              err.Error(),
				"candidates":         []interface{}{},
			})
			continue
		}

		filterChainJSON, _ := json.Marshal(result.Summary.Filters)
		store.InsertScanStat(ctx, &db.ScanStat{
			ScanID:      scanID,
			VulnType:    vulnType,
			SeedCount:   result.Summary.SeedCount,
			FinalCount:  len(result.Candidates),
			FilterChain: string(filterChainJSON),
		})

		if len(result.Summary.Dropped) > 0 {
			dismissedByVuln = append(dismissedByVuln, report.VulnTypeDismissed{
				VulnerabilityType: vulnType,
				DroppedCount:      len(result.Summary.Dropped),
				DroppedByReason:   result.Summary.DroppedByReason,
				Dropped:           result.Summary.Dropped,
			})
			totalDropped += len(result.Summary.Dropped)
		}

		for _, c := range result.Candidates {
			if c.Target.File != "" {
				filesWithCandidates[c.Target.File] = true
			}
		}
		totalCandidates += len(result.Candidates)
		evidencePackages = append(evidencePackages, map[string]interface{}{
			"vulnerability_type": vulnType,
			"summary":            result.Summary,
			"candidates":         result.Candidates,
		})
	}

	findings, _ := store.ListFindings(ctx)
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
	summaryData := report.SummaryData{
		ScanID:           scanID,
		TargetPath:       absPath,
		ScanDir:          scanDir,
		TotalCandidates:  totalCandidates,
		FilesIndexed:     indexResult.FilesIndexed,
		FunctionsIndexed: indexResult.FunctionsIndexed,
		TypeBreakdown:    typeBreakdown,
		ReportPath:       filepath.Join(scanDir, report.ReportFile),
		SarifPath:        filepath.Join(scanDir, report.SarifFile),
		LatestPath:       filepath.Join(scansDir, report.LatestName),
	}
	summaryStr := report.BuildScanSummary(summaryData)

	output := map[string]interface{}{
		"scan_id":               scanID,
		"evidence_packages":     evidencePackages,
		"total_candidates":      totalCandidates,
		"files_with_candidates": filesList,
		"index_summary": map[string]interface{}{
			"files_indexed":     indexResult.FilesIndexed,
			"functions_indexed": indexResult.FunctionsIndexed,
			"files_skipped":     indexResult.FilesSkipped,
		},
		"existing_findings": findingsList,
		"target_path":       absPath,
		"scan_dir":          scanDir,
		"_summary":          summaryStr,
	}

	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Fprintln(os.Stdout, string(jsonBytes))

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
		RootDir:    absPath,
		ScanDir:    scanDir,
		SarifPath:  filepath.Join(scanDir, report.SarifFile),
		ReportPath: filepath.Join(scanDir, report.ReportFile),
		ScanID:     scanID,
	}
	if err := scanOutput.Write(planResults, report.IndexSummary{
		FilesIndexed:     indexResult.FilesIndexed,
		FunctionsIndexed: indexResult.FunctionsIndexed,
		FilesSkipped:     indexResult.FilesSkipped,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write output: %v\n", err)
	} else {
		if logCloser != nil {
			if cerr := logCloser.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to close scan log: %v\n", cerr)
			}
			logCloser = nil
		}
		scansDir := filepath.Dir(scanOutput.ScanDir)
		if serr := report.UpdateLatest(scansDir, scanOutput.ScanID); serr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update latest symlink: %v\n", serr)
		}
	}

	report.PrintScanSummary(os.Stderr, summaryData)

	if err := report.WriteDismissed(scanDir, report.DismissedSummary{
		ScanID:       scanID,
		TotalDropped: totalDropped,
		ByVulnType:   dismissedByVuln,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write dismissed ledger: %v\n", err)
	}

	return 0
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
	logger, closer := log.NewMultiWriter(os.Stderr, f, log.LevelInfo)
	return logger, closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

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

	files, _ := store.ListFiles(ctx)
	funcs, _ := store.ListFunctions(ctx)

	allEvents := 0
	for _, et := range planner.AllSeedEventTypes() {
		events, _ := store.ListEventsByType(ctx, et)
		allEvents += len(events)
	}
	for _, et := range []string{"NULL_VALUE", "NULL_GUARD", "MEMORY_RELEASE", "RESOURCE_RELEASE", "VALUE_INIT"} {
		events, _ := store.ListEventsByType(ctx, et)
		allEvents += len(events)
	}

	findings, _ := store.ListFindings(ctx)

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
