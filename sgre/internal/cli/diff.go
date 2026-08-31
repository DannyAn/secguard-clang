package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/git"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// runDiffCmd implements `secguard diff [<base>]` — review only the changes
// between <base> (default HEAD~1) and HEAD.
func runDiffCmd(ctx context.Context, args []string) int {
	return runReviewCmd(ctx, "diff", args)
}

// runPrCmd implements `secguard pr [--base <branch>]` — review a PR/MR diff,
// with base defaulting to the merge-base of HEAD and main/master.
func runPrCmd(ctx context.Context, args []string) int {
	return runReviewCmd(ctx, "pr", args)
}

// runMrCmd is the GitLab alias of pr.
func runMrCmd(ctx context.Context, args []string) int {
	return runReviewCmd(ctx, "mr", args)
}

func runReviewCmd(ctx context.Context, kind string, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	baseArg := parseStringFlag(remaining, "base")
	remaining = removeFlag(remaining, "base")
	excludeDirs, _ := parseExcludeFlag(remaining)
	remaining = removeFlag(remaining, "exclude")

	var targetPath string
	switch kind {
	case "diff":
		// `secguard diff [<base>]` — the positional arg is the diff base (matching
		// `/secguard git diff HEAD~1`); the review always targets the repo root.
		if len(remaining) > 0 && baseArg == "" {
			baseArg = remaining[0]
		}
		targetPath = "."
	default: // pr / mr
		if len(remaining) == 0 {
			remaining = []string{"."}
		}
		targetPath = remaining[0]
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

	projectRoot, err := os.Getwd()
	if err != nil || projectRoot == "" {
		projectRoot = absPath
	}
	dbPath = resolveDBPath(dbExplicit, dbPath, projectRoot)

	// An incremental review is only meaningful inside a git working tree. Do NOT
	// fall back to a full scan here: a caller that asked for a diff must get a
	// diff, not a silently-scoped full scan.
	if !git.IsRepo(projectRoot) {
		WriteErrorJSON("incremental review requires a git working tree (run from inside a git repo)")
		return 1
	}

	head, err := git.RevParse(projectRoot, "HEAD")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to resolve HEAD: %v", err))
		return 1
	}

	baseRef, base, err := resolveBase(projectRoot, kind, baseArg)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to resolve diff base: %v", err))
		return 1
	}

	reviewID := reviewIDFor(kind, base, head)
	reviewDir := filepath.Join(projectRoot, report.CodeagentDir, report.ProductDir, report.ReviewsDir, reviewID)
	if err := os.MkdirAll(reviewDir, 0755); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to create review dir: %v", err))
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to create db directory: %v", err))
		return 1
	}

	d, err := git.ComputeDiff(projectRoot, base, head)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to compute diff: %v", err))
		return 1
	}
	lineSets := buildChangedLines(d.Files, projectRoot)
	changedJSON, _ := json.Marshal(d.Files)

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	logger, logCloser := newScanLogger(reviewDir)
	defer func() {
		if logCloser != nil {
			_ = logCloser.Close()
		}
	}()

	if err := store.UpsertReviewSession(ctx, &db.ReviewSession{
		ReviewID:     reviewID,
		Kind:         kind,
		BaseRef:      baseRef,
		HeadRef:      "HEAD",
		BaseSHA:      base,
		HeadSHA:      head,
		ChangedFiles: string(changedJSON),
		Status:       "running",
	}); err != nil {
		logger.Warn("upsert review session failed", "error", err)
	}

	sup := loadSuppressions(ctx, store)
	baselineFp, err := store.ListFingerprintsExcludingScanID(ctx, reviewID)
	if err != nil {
		logger.Warn("load baseline fingerprints failed", "error", err)
		baselineFp = map[string]bool{}
	}

	logger.Info("review started", "review_id", reviewID, "kind", kind, "base", base, "head", head, "changed_files", len(d.Files))

	outcome, err := runPipeline(ctx, store, logger, absPath, excludeDirs)
	if err != nil {
		_ = store.UpdateReviewSessionStatus(ctx, reviewID, "failed")
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
		cwe := report.VulnToCWE(vulnType)

		// Incremental scoping: keep only candidates whose sink line OR flow-source
		// line lands on a changed line, then drop any whose fingerprint already
		// exists in a prior full scan or review (i.e. not a new problem).
		scoped := scopeToDiffLines(result.Candidates, lineSets)
		scoped, baselineExisting := filterByBaselineFingerprint(scoped, baselineFp, cwe)
		kept, suppressedCount, _ := filterSuppressedCandidates(scoped, cwe, sup, nil)
		totalSuppressed += suppressedCount
		totalBaselineExisting += baselineExisting

		autoConfirmed, needsReview := splitBySuspicion(kept)
		autoWritten, autoErr := autoConfirmFindings(ctx, store, reviewID, vulnType, autoConfirmed)
		if autoErr != nil {
			logger.Warn("auto-confirm findings failed", "vuln_type", vulnType, "error", autoErr)
		}
		totalAutoConfirmed += autoWritten

		if _, err := store.InsertScanStat(ctx, &db.ScanStat{
			ScanID:      reviewID,
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

	filesList := make([]string, 0, len(filesWithCandidates))
	for f := range filesWithCandidates {
		filesList = append(filesList, f)
	}
	sort.Strings(filesList)

	candidatesByType := make(map[string]int, len(evidencePackages))
	for _, ep := range evidencePackages {
		vt, _ := ep["vulnerability_type"].(string)
		cands, _ := ep["candidates"].([]planner.EvidenceItem)
		candidatesByType[vt] = len(cands)
	}

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		logger.Warn("list functions failed", "error", err)
	}
	functionsInIndex := len(funcs)

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
		ScanDir:             reviewDir,
		SarifPath:           filepath.Join(reviewDir, report.SarifFile),
		CandidatesSarifPath: filepath.Join(reviewDir, report.CandidatesSarifFile),
		ReportPath:          filepath.Join(reviewDir, report.ReportFile),
		ScanID:              reviewID,
	}
	if err := scanOutput.Write(planResults, report.IndexSummary{
		FilesIndexed:     indexResult.FilesIndexed,
		FunctionsIndexed: indexResult.FunctionsIndexed,
		FunctionsInIndex: functionsInIndex,
		FilesSkipped:     indexResult.FilesSkipped,
	}); err != nil {
		_ = store.UpdateReviewSessionStatus(ctx, reviewID, "failed")
		WriteErrorJSON(fmt.Sprintf("failed to write review output: %v", err))
		return 1
	}
	if logCloser != nil {
		_ = logCloser.Close()
		logCloser = nil
	}

	_ = store.UpdateReviewSessionStatus(ctx, reviewID, "done")

	output := map[string]interface{}{
		"review_id":              reviewID,
		"kind":                   kind,
		"base":                   base,
		"head":                   head,
		"changed_files":          len(d.Files),
		"candidates_by_type":     candidatesByType,
		"plan_errors":            planErrors,
		"total_candidates":       totalCandidates,
		"auto_confirmed_count":   totalAutoConfirmed,
		"suppressed_count":       totalSuppressed,
		"baseline_existing_count": totalBaselineExisting,
		"files_with_candidates_count": len(filesList),
		"index_summary": map[string]interface{}{
			"files_indexed":      indexResult.FilesIndexed,
			"functions_indexed":  indexResult.FunctionsIndexed,
			"functions_in_index": functionsInIndex,
			"files_skipped":      indexResult.FilesSkipped,
		},
		"target_path":      absPath,
		"review_dir":       reviewDir,
		"candidates_sarif": filepath.Join(reviewDir, report.CandidatesSarifFile),
		"result_sarif_note": fmt.Sprintf("%s is written by `report --audit` after classification; the review writes %s (unclassified leads at level \"note\")", report.SarifFile, report.CandidatesSarifFile),
	}

	WriteJSON(output)
	return 0
}

// resolveBase returns the base ref label and its resolved SHA for a review kind.
func resolveBase(projectRoot, kind, baseArg string) (string, string, error) {
	switch kind {
	case "diff":
		ref := baseArg
		if ref == "" {
			ref = "HEAD~1"
		}
		sha, err := git.RevParse(projectRoot, ref)
		if err != nil {
			return "", "", err
		}
		return ref, sha, nil
	default: // pr / mr
		ref := baseArg
		if ref == "" {
			ref = detectDefaultBranch(projectRoot)
		}
		sha, err := git.MergeBase(projectRoot, "HEAD", ref)
		if err != nil {
			return "", "", err
		}
		return ref, sha, nil
	}
}

func detectDefaultBranch(repoDir string) string {
	for _, name := range []string{"main", "master"} {
		for _, candidate := range []string{"origin/" + name, name} {
			if _, err := git.RevParse(repoDir, candidate); err == nil {
				return candidate
			}
		}
	}
	return "main"
}

func reviewIDFor(kind, base, head string) string {
	return kind + "_" + shortSHA(base) + "_" + shortSHA(head)
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// buildChangedLines maps each changed file's absolute path to its set of
// added-line numbers, for candidate scoping.
func buildChangedLines(files []git.FileDiff, repoRoot string) map[string]map[int]bool {
	out := make(map[string]map[int]bool, len(files))
	for _, f := range files {
		if f.Status == "D" {
			continue
		}
		abs := filepath.Join(repoRoot, filepath.FromSlash(f.Path))
		set := make(map[int]bool, len(f.Lines))
		for _, l := range f.Lines {
			set[l] = true
		}
		out[abs] = set
	}
	return out
}

// scopeToDiffLines keeps a candidate only when its file is in the changed set
// and either its sink line (Target.Line) or its flow-source line (SourceLine)
// lands on a changed line. The source-line rule captures "a change at line 10
// makes the dereference at line 500 dangerous" for flow-based vuln types.
func scopeToDiffLines(items []planner.EvidenceItem, lineSets map[string]map[int]bool) []planner.EvidenceItem {
	kept := make([]planner.EvidenceItem, 0, len(items))
	for _, it := range items {
		set, ok := lineSets[it.Target.File]
		if !ok {
			continue
		}
		if set[it.Target.Line] || (it.SourceLine > 0 && set[it.SourceLine]) {
			kept = append(kept, it)
		}
	}
	return kept
}

// filterByBaselineFingerprint drops candidates whose content fingerprint already
// exists in a prior full scan or review. It returns the kept candidates and the
// count already seen (the "not new" tier).
func filterByBaselineFingerprint(items []planner.EvidenceItem, baseline map[string]bool, cwe string) (kept []planner.EvidenceItem, existing int) {
	kept = make([]planner.EvidenceItem, 0, len(items))
	for _, it := range items {
		fp := computeFingerprint(cwe, it.Target.File, it.Target.Function, it.Target.Line)
		if baseline[fp] {
			existing++
			continue
		}
		kept = append(kept, it)
	}
	return kept, existing
}
