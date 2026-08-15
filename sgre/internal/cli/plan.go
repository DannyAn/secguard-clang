package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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

	funcs, _ := store.ListFunctions(ctx)
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
		"candidates":         result.Candidates,
		"summary":            result.Summary,
		"_summary":           summaryStr,
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to serialize result: %v", err))
		return 1
	}
	fmt.Fprintln(os.Stdout, string(data))

	report.PrintPlanSummary(os.Stderr, planSummaryData)

	return 0
}
