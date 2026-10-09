package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/git"
	"github.com/DannyAn/secguard-clang/internal/review"
	"github.com/DannyAn/secguard-clang/internal/review/aireview"
)

func runReviewAutoConfirmedCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	dbPath, found := resolveExistingDBPath(dbExplicit, dbPath)
	if !found {
		WriteErrorJSON("no sgre.db found; run 'secguard scan <path>' first")
		return 1
	}

	scanID := parseStringFlag(remaining, "scan-id")
	remaining = removeFlag(remaining, "scan-id")
	typeFilter := parseStringFlag(remaining, "type")
	remaining = removeFlag(remaining, "type")
	limit := parseIntFlag(remaining, "limit")
	remaining = removeFlag(remaining, "limit")
	dryRun := hasFlag(remaining, "dry-run")
	remaining = removeFlag(remaining, "dry-run")
	statusMode := hasFlag(remaining, "status")
	remaining = removeFlag(remaining, "status")
	outputJSON := hasFlag(remaining, "output-json")
	remaining = removeFlag(remaining, "output-json")

	projectRoot, err := os.Getwd()
	if err != nil || projectRoot == "" {
		WriteErrorJSON(fmt.Sprintf("failed to get project root: %v", err))
		return 1
	}

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	cfg, err := config.LoadE()
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to load configuration: %v", err))
		return 1
	}

	if scanID == "" {
		latest, lerr := store.GetLatestScanID(ctx)
		if lerr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", lerr))
			return 1
		}
		scanID = latest
	}

	if scanID == "" {
		fmt.Fprintln(os.Stdout, `{"reviewed_count":0}`)
		return 0
	}

	run, rerr := store.GetScanRun(ctx, scanID)
	if rerr != nil {
		WriteErrorJSON(fmt.Sprintf("failed to get scan run: %v", rerr))
		return 1
	}
	if run == nil {
		fmt.Fprintln(os.Stdout, `{"reviewed_count":0}`)
		return 0
	}

	if statusMode {
		return runReviewStatus(ctx, store, scanID)
	}

	aiCfg := &cfg.AIReview
	if !dryRun && (aiCfg.Provider == "" || aiCfg.Endpoint == "") {
		WriteErrorJSON("ai provider not configured")
		return 1
	}

	var vulnTypes []string
	if typeFilter != "" {
		for _, vt := range strings.Split(typeFilter, ",") {
			if vt = strings.TrimSpace(vt); vt != "" {
				vulnTypes = append(vulnTypes, vt)
			}
		}
	}

	filter := review.RunFilter{
		ScanID:    scanID,
		VulnTypes: vulnTypes,
		Limit:     limit,
	}

	reviewedRevision, treeDirty := resolveCurrentRevision(projectRoot)

	opts := review.RunOptions{
		DryRun:           dryRun,
		ProjectRoot:      projectRoot,
		ScanSourceRev:    run.SourceRevision,
		ReviewedRevision: reviewedRevision,
		TreeDirty:        treeDirty,
	}

	var reviewer review.Reviewer
	if !dryRun {
		reviewer = aireview.NewHTTPReviewer(aiCfg)
	}

	logger := defaultLogger()
	coord := review.NewCoordinator(store, reviewer, aiCfg, projectRoot, logger)
	result, rerr2 := coord.Run(ctx, filter, opts)
	if rerr2 != nil {
		WriteErrorJSON(fmt.Sprintf("review failed: %v", rerr2))
		return 1
	}

	if outputJSON {
		_ = WriteJSON(result)
	} else {
		fmt.Fprint(os.Stdout, review.NewReportSummarizer().RenderReport(result))
	}
	return 0
}

func resolveCurrentRevision(projectRoot string) (string, bool) {
	if !git.IsRepo(projectRoot) {
		return "", true
	}
	sha, err := git.RevParse(projectRoot, "HEAD")
	if err != nil {
		return "", true
	}
	return sha, git.WorkingTreeDirty(projectRoot)
}

func runReviewStatus(ctx context.Context, store db.Store, scanID string) int {
	findings, err := store.ListFindingsByScanID(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list findings: %v", err))
		return 1
	}
	stats := map[string]int{
		"total":          0,
		"auto_confirmed": 0,
		"reviewed":       0,
		"unreviewed":     0,
	}
	for _, f := range findings {
		if f.Status != db.StatusAutoConfirmed {
			continue
		}
		stats["auto_confirmed"]++
		stats["total"]++
		switch f.ReviewStatus {
		case "ai_confirmed", "false_positive", "needs_more_evidence":
			stats["reviewed"]++
		default:
			stats["unreviewed"]++
		}
	}
	_ = WriteJSON(stats)
	return 0
}
