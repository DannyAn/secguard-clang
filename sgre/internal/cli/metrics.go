package cli

import (
	"context"
	"fmt"
	"math"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// renderScanMetrics returns the plain-key scan metrics map written into the
// `secguard scan` stdout envelope. Durations are milliseconds; candidate counts
// are raw, so the reduction % stays a read-time derivation rather than a stored
// number the team cannot re-derive.
func renderScanMetrics(r *db.ScanRun) map[string]interface{} {
	return map[string]interface{}{
		"duration_ms":       r.DurationMs,
		"index_ms":          r.IndexMs,
		"graph_ms":          r.GraphMs,
		"detectors_ms":      r.DetectorsMs,
		"plan_ms":           r.PlanMs,
		"report_ms":         r.ReportMs,
		"files_indexed":     r.FilesIndexed,
		"functions_indexed": r.FunctionsIndexed,
		"seed_count":        r.SeedCount,
		"final_count":       r.FinalCount,
		"report_bytes":      r.ReportBytes,
		"evidence_bytes":    r.EvidenceBytes,
	}
}

// runMetricsCmd prints the scan-level performance/convergence summary recorded
// by `secguard scan`. It reads the latest scan by default; --scan-id selects a
// specific one; --all lists recent runs (newest first). The output is JSON on
// stdout, matching every other secguard command.
func runMetricsCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	dbPath = resolveDBPath(dbExplicit, dbPath, ".")

	scanID := parseStringFlag(remaining, "scan-id")
	remaining = removeFlag(remaining, "scan-id")
	listAll := hasFlag(remaining, "all") || hasFlag(remaining, "list")
	remaining = removeFlag(remaining, "all")
	remaining = removeFlag(remaining, "list")

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	if listAll {
		runs, err := store.ListScanRuns(ctx, 100)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to list scan runs: %v", err))
			return 1
		}
		out := make([]map[string]interface{}, 0, len(runs))
		for _, r := range runs {
			out = append(out, metricsView(r))
		}
		_ = WriteJSON(out)
		return 0
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
		WriteErrorJSON("no scan metrics found; run 'secguard scan <path>' first or pass --scan-id")
		return 1
	}
	run, err := store.GetScanRun(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to get scan run: %v", err))
		return 1
	}
	if run == nil {
		WriteErrorJSON(fmt.Sprintf("scan %q has no metrics row (it may predate scan metrics, or be a diff/pr review); run 'secguard scan <path>' to record one", scanID))
		return 1
	}
	_ = WriteJSON(metricsView(run))
	return 0
}

// metricsView renders one scan run for `secguard metrics`: the raw fields plus
// read-time derived values (seconds, phase breakdown, candidate reduction %)
// that are easier for a person to read than bare millisecond counts.
func metricsView(r *db.ScanRun) map[string]interface{} {
	reduction := 0.0
	if r.SeedCount > 0 {
		reduction = float64(r.SeedCount-r.FinalCount) / float64(r.SeedCount) * 100
		if reduction < 0 {
			reduction = 0
		}
	}
	return map[string]interface{}{
		"scan_id":      r.ScanID,
		"duration_ms":  r.DurationMs,
		"duration_sec": round1(float64(r.DurationMs) / 1000),
		"phases_ms": map[string]int64{
			"index":     r.IndexMs,
			"graph":     r.GraphMs,
			"detectors": r.DetectorsMs,
			"plan":      r.PlanMs,
			"report":    r.ReportMs,
		},
		"files_indexed":     r.FilesIndexed,
		"functions_indexed": r.FunctionsIndexed,
		"candidates": map[string]interface{}{
			"seed_count":    r.SeedCount,
			"final_count":   r.FinalCount,
			"reduction_pct": round1(reduction),
		},
		"report_bytes":   r.ReportBytes,
		"evidence_bytes": r.EvidenceBytes,
		// tokens_est is a read-time estimate of the AI's input volume, not a
		// measured LLM billing figure: the agent has no token meter in the Go
		// pipeline, so it is approximated as bytes ÷ 4. Store only the bytes;
		// derive the estimate here so it is never mistaken for a fact.
		"tokens_est": int64(float64(r.ReportBytes+r.EvidenceBytes) / 4),
	}
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
