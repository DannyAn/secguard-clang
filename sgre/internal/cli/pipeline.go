package cli

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// pipelineOutcome is the raw converged-candidate output of the analysis
// pipeline, before any full-scan or incremental-review post-processing (suppression,
// target/line scoping, auto-confirm, scan_stats, report rendering). Both the full
// scan and the incremental review consume this shared, behavior-identical stage.
type pipelineOutcome struct {
	Index      *indexer.IndexResult
	Plans      []*planner.PlanResult
	PlanErrors map[string]string
	// Timings are the per-phase wall-clock durations (milliseconds) captured
	// across the shared engine. They feed the scan-level scan_runs metrics so
	// performance is queryable over time instead of only in the scan log.
	Timings pipelineTimings
}

// pipelineTimings are the raw phase durations runPipeline measured. They are
// plain milliseconds — no derived ratios — so the scan_runs table stores honest
// facts the team can re-derive at read time.
type pipelineTimings struct {
	IndexMs     int64
	GraphMs     int64
	DetectorsMs int64
	PlanMs      int64
}

// runPipeline runs the shared engine: index → graph build → detectors → plan.
// It is the ONLY place the semantic-graph/evidence/convergence stages run, so a
// full scan and an incremental review can never drift in how they analyze code.
// excludeDirs is nil to keep the default exclusions, or an explicit (possibly
// empty) list to override them.
func runPipeline(ctx context.Context, store db.Store, logger *log.Logger, absPath string, excludeDirs []string) (*pipelineOutcome, error) {
	// Validate the static vuln-type registry (spec + filter chain) BEFORE the
	// expensive index/graph/detector phases. A registry typo that would otherwise
	// surface only as a per-type Plan failure after a long scan now fails the run
	// immediately, at zero cost.
	if err := planner.ValidateRegistry(); err != nil {
		return nil, fmt.Errorf("planner registry: %w", err)
	}

	p := parser.NewParser()
	defer p.CloseAll()

	var timings pipelineTimings

	idx := indexer.NewIndexer(store, logger)
	if excludeDirs != nil {
		idx.SetExcludeDirs(excludeDirs)
	}

	idxStart := time.Now()
	indexResult, err := idx.Index(ctx, absPath)
	if err != nil {
		return nil, fmt.Errorf("index failed: %w", err)
	}
	timings.IndexMs = time.Since(idxStart).Milliseconds()
	logger.Info("phase timing", "phase", "index", "elapsed_ms", timings.IndexMs)

	// The semantic graph is rebuilt from scratch every run (there is no
	// incremental graph update), so clear the previous run's nodes/edges first.
	if err := store.ClearGraph(ctx); err != nil {
		return nil, fmt.Errorf("clear graph: %w", err)
	}

	graphStart := time.Now()
	type builderTask struct {
		name string
		fn   func(context.Context) error
	}
	builders := []builderTask{
		{"call_graph", func(ctx context.Context) error {
			_, err := graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"data_flow", func(ctx context.Context) error {
			_, err := graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"alias", func(ctx context.Context) error {
			_, err := graph.NewAliasBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"ownership", func(ctx context.Context) error {
			_, err := graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"interproc", func(ctx context.Context) error {
			_, err := graph.NewInterprocBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"lock_order", func(ctx context.Context) error {
			_, err := graph.NewLockOrderBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"shared_access", func(ctx context.Context) error {
			_, err := graph.NewSharedAccessBuilder(store, p, logger).Build(ctx)
			return err
		}},
	}
	var bwg sync.WaitGroup
	bErrCh := make(chan error, len(builders))
	for _, b := range builders {
		bwg.Add(1)
		go func(b builderTask) {
			defer bwg.Done()
			defer func() {
				if r := recover(); r != nil {
					bErrCh <- fmt.Errorf("%s panicked: %v", b.name, r)
				}
			}()
			if err := b.fn(ctx); err != nil {
				bErrCh <- fmt.Errorf("%s: %w", b.name, err)
			}
		}(b)
	}
	bwg.Wait()
	close(bErrCh)
	for err := range bErrCh {
		return nil, fmt.Errorf("graph build failed: %w", err)
	}
	timings.GraphMs = time.Since(graphStart).Milliseconds()
	logger.Info("phase timing", "phase", "graph_builders_parallel", "elapsed_ms", timings.GraphMs)

	if err := store.ClearSecurityEvents(ctx); err != nil {
		return nil, fmt.Errorf("clear security events: %w", err)
	}

	detStart := time.Now()
	if err := evidence.RunAllDetectors(ctx, store, p, logger); err != nil {
		return nil, fmt.Errorf("detectors failed: %w", err)
	}
	timings.DetectorsMs = time.Since(detStart).Milliseconds()
	logger.Info("phase timing", "phase", "detectors_total", "elapsed_ms", timings.DetectorsMs)

	vulnTypes := planner.AllVulnTypes()
	plans := make([]*planner.PlanResult, len(vulnTypes))
	planErrors := map[string]string{}
	// planErrors is written from up to planConcurrency goroutines. Go maps have
	// undefined behavior on concurrent writes even to different keys, so a
	// simultaneous failure/panic in two vuln types would crash the process with
	// "concurrent map writes" (unrecoverable by recover). A mutex makes those
	// writes safe.
	var planErrMu sync.Mutex

	// One Planner is shared across every vuln type. The Planner's only shared
	// mutable state is its callReachCache (a sync.Mutex + done flag that caches
	// only a SUCCESS so a transient failure is retried), which exists to compute
	// call-graph reachability once per scan instead of once per type. Plan()
	// keeps all per-type state local, so concurrent Plan calls are safe (the
	// shared parser is internally synchronized).
	pl := planner.NewPlanner(store, p, logger)

	const planConcurrency = 4
	planSem := make(chan struct{}, planConcurrency)
	var pwg sync.WaitGroup
	planStart := time.Now()
	for i, vulnType := range vulnTypes {
		pwg.Add(1)
		go func(idx int, vt string) {
			defer pwg.Done()
			defer func() {
				if r := recover(); r != nil {
					planErrMu.Lock()
					planErrors[vt] = fmt.Sprintf("plan %s panicked: %v", vt, r)
					planErrMu.Unlock()
				}
			}()
			planSem <- struct{}{}
			defer func() { <-planSem }()
			planStart := time.Now()
			result, err := pl.Plan(ctx, vt)
			if logger != nil {
				logger.Info("phase timing", "phase", "plan_"+vt, "elapsed_ms", time.Since(planStart).Milliseconds())
			}
			if err != nil {
				planErrMu.Lock()
				planErrors[vt] = err.Error()
				planErrMu.Unlock()
				return
			}
			plans[idx] = result
		}(i, vulnType)
	}
	pwg.Wait()
	timings.PlanMs = time.Since(planStart).Milliseconds()

	return &pipelineOutcome{
		Index:      indexResult,
		Plans:      plans,
		PlanErrors: planErrors,
		Timings:    timings,
	}, nil
}
