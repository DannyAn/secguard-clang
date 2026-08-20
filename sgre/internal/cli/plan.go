package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

func runPlanCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	if len(remaining) == 0 {
		WriteErrorJSON("plan requires a vulnerability type argument")
		return 1
	}
	vulnType := remaining[0]

	dbPath = resolveDBPath(dbExplicit, dbPath, ".")

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list functions: %v", err))
		return 1
	}
	if len(funcs) == 0 {
		WriteErrorJSON("no indexed repository found; run `secguard index <path>` first")
		return 1
	}

	logger := defaultLogger()
	p := planner.NewPlanner(store, parser.NewParser(), logger)

	result, err := p.Plan(ctx, vulnType)
	if err != nil {
		WriteErrorJSON(err.Error())
		return 1
	}

	candidates := make([]report.PlanCandidateEntry, 0, len(result.Candidates))
	for _, c := range result.Candidates {
		candidates = append(candidates, report.PlanCandidateEntry{
			Function:  c.Target.Function,
			File:      c.Target.File,
			Line:      c.Target.Line,
			Variable:  c.Target.Variable,
			Suspicion: c.SuspicionLevel,
		})
	}
	filters := make([]report.PlanFilterStat, 0, len(result.Summary.Filters))
	for _, f := range result.Summary.Filters {
		filters = append(filters, report.PlanFilterStat{
			Name:        f.Name,
			InputCount:  f.InputCount,
			OutputCount: f.OutputCount,
		})
	}
	planSummaryData := report.PlanSummaryData{
		VulnType:   result.VulnerabilityType,
		CWE:        report.VulnToCWE(result.VulnerabilityType),
		SeedCount:  result.Summary.SeedCount,
		FinalCount: result.Summary.FinalCount,
		Filters:    filters,
		Candidates: candidates,
	}
	summaryStr := report.BuildPlanSummary(planSummaryData)

	output := map[string]interface{}{
		"vulnerability_type": result.VulnerabilityType,
		"cwe":                report.VulnToCWE(result.VulnerabilityType),
		"candidates":         result.Candidates,
		"summary":            result.Summary,
		"_summary":           summaryStr,
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to serialize result: %v", err))
		return 1
	}

	// 完整 candidates 写到文件，stdout 只返回摘要 + 文件路径。
	// 避免大量 candidates（259+ 条）打印到 agent 上下文。
	candidatesFile := filepath.Join(filepath.Dir(dbPath), fmt.Sprintf("plan-%s-%d.json", vulnType, time.Now().Unix()))
	if werr := os.WriteFile(candidatesFile, data, 0644); werr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write candidates file: %v\n", werr)
	}

	summaryOutput := map[string]interface{}{
		"vulnerability_type": result.VulnerabilityType,
		"cwe":                report.VulnToCWE(result.VulnerabilityType),
		"deduped_count":      result.Summary.DedupedCount,
		"seed_count":         result.Summary.SeedCount,
		"final_count":        result.Summary.FinalCount,
		"candidate_count":    len(result.Candidates),
		"candidates_file":    candidatesFile,
		"filters":            filters,
	}
	summaryData, _ := json.MarshalIndent(summaryOutput, "", "  ")
	fmt.Fprintln(os.Stdout, string(summaryData))

	report.PrintPlanSummary(os.Stderr, planSummaryData)

	return 0
}
