package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
	"github.com/DannyAn/secguard-clang/internal/worker"
)

// runClassifyCmd is the route-B deterministic executor entry point. agent mode
// (default) is the status-quo LLM-orchestrator path; executor mode re-plans the
// scan deterministically and classifies the converged candidates through the
// worker executor instead of a subagent fan-out. --dry-run uses DismissAllRunner
// so the wiring (re-plan -> batch -> assemble -> run -> audit -> persist) is
// exercised without an LLM.
func runClassifyCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	mode := parseStringFlag(remaining, "mode")
	remaining = removeFlag(remaining, "mode")
	dryRun := hasFlag(remaining, "dry-run")
	remaining = removeFlag(remaining, "dry-run")
	batchSize := parseIntFlag(remaining, "batch-size")
	remaining = removeFlag(remaining, "batch-size")
	if batchSize <= 0 {
		batchSize = 20
	}

	if mode == "" || mode == "agent" {
		WriteJSON(map[string]string{"mode": "agent", "note": "agent mode is the LLM-orchestrator classification path; nothing to run here"})
		return 0
	}
	if mode != "executor" {
		WriteErrorJSON(fmt.Sprintf("invalid --mode %q (expected agent|executor)", mode))
		return 1
	}

	if len(remaining) == 0 {
		remaining = []string{"."}
	}
	absPath, err := filepath.Abs(remaining[0])
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

	outcome, err := runPipeline(ctx, store, log.Default(), absPath, nil, nil)
	if err != nil {
		WriteErrorJSON(err.Error())
		return 1
	}

	var runner worker.Runner = worker.DismissAllRunner{}
	if !dryRun {
		runner = worker.NewSubprocessRunner(nil)
	}
	ex := worker.NewExecutor(runner, worker.ExecutorConfig{Concurrency: 10, InconclusiveEscalation: 0.2})

	scanOutput := report.NewScanOutput(projectRoot)
	scanID := scanOutput.ScanID

	type typeSummary struct {
		Candidates  int `json:"candidates"`
		Written     int `json:"written"`
		Dismissed   int `json:"dismissed"`
		Inconclusive int `json:"inconclusive"`
		Missing     int `json:"missing"`
		Escalated   int `json:"escalated"`
	}
	byType := map[string]*typeSummary{}

	for _, pkg := range outcome.Plans {
		if pkg == nil || len(pkg.Candidates) == 0 {
			continue
		}
		vt := pkg.VulnerabilityType
		// Auto-confirm the pipeline-PROVED tier (suspicion "confirmed" and no
		// macro context) exactly like the scan does, so the executor only judges
		// suspected/possible candidates and never re-decides a machine proof.
		autoConfirmed, needsReview := splitBySuspicion(pkg.Candidates)
		if _, _, aerr := autoConfirmFindings(ctx, store, scanID, vt, autoConfirmed, log.Default()); aerr != nil {
			WriteErrorJSON(fmt.Sprintf("auto-confirm %s: %v", vt, aerr))
			return 1
		}
		if _, err := store.InsertScanStat(ctx, &db.ScanStat{
			ScanID:     scanID,
			VulnType:   vt,
			SeedCount:  pkg.Summary.SeedCount,
			FinalCount: distinctFindingLocations(needsReview),
		}); err != nil {
			WriteErrorJSON(fmt.Sprintf("insert scan stat %s: %v", vt, err))
			return 1
		}

		sum := &typeSummary{Candidates: len(needsReview)}
		byType[vt] = sum
		if len(needsReview) == 0 {
			if err := store.MarkAIStageDone(ctx, scanID, vt); err != nil {
				_ = err
			}
			continue
		}

		var batches []worker.Batch
		for start := 0; start < len(needsReview); start += batchSize {
			end := start + batchSize
			if end > len(needsReview) {
				end = len(needsReview)
			}
			batches = append(batches, worker.Batch{Type: vt, RangeStart: start, RangeEnd: end, Candidates: needsReview})
		}
		results := ex.Run(ctx, batches)

		for bi, res := range results {
			if res.Err != "" {
				sum.Missing += len(batches[bi].Candidates)
				continue
			}
			batch := batches[bi]
			for _, v := range res.Verdicts {
				idx := v.Seq - 1 - batch.RangeStart
				if idx < 0 || idx >= len(batch.Candidates) {
					continue
				}
				c := batch.Candidates[idx]
				if v.Status == "confirmed" {
					if err := upsertExecutorFinding(ctx, store, scanID, batch.Type, c, v); err != nil {
						WriteErrorJSON(fmt.Sprintf("persist verdict %d: %v", v.Seq, err))
						return 1
					}
					sum.Written++
				} else if v.Status == "dismissed" {
					sum.Dismissed++
				} else {
					sum.Inconclusive++
				}
			}
			sum.Missing += len(res.MissingSeqs)
			if res.Escalate {
				sum.Escalated++
			}
		}
		if err := store.MarkAIStageDone(ctx, scanID, vt); err != nil {
			_ = err
		}
	}

	WriteJSON(map[string]interface{}{"scan_id": scanID, "mode": "executor", "dry_run": dryRun, "types": byType})
	return 0
}

func upsertExecutorFinding(ctx context.Context, store db.Store, scanID, vulnType string, c planner.EvidenceItem, v worker.Verdict) error {
	cwe := report.VulnToCWEForCategory(vulnType, c.Category)
	if v.CWE != "" {
		cwe = v.CWE
	}
	f := &db.Finding{
		RuleID:       cwe,
		Severity:     "high",
		Confidence:   1.0,
		Status:       "confirmed",
		FilePath:     c.Target.File,
		LineNumber:   c.Target.Line,
		FunctionName: c.Target.Function,
		Variable:     c.Target.Variable,
		Summary:      c.Hint,
		Reasoning:    v.Reason,
		ScanID:       scanID,
		Fingerprint:  computeFingerprint(cwe, c.Target.File, c.Target.Function, c.Target.Line),
	}
	_, err := store.UpsertFinding(ctx, f)
	return err
}
