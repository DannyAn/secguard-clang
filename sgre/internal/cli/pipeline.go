package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/DannyAn/secguard-clang/internal/config"
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
	// DetectorErrors records any detector that failed (panicked or returned an
	// error) without aborting the run. It is surfaced alongside PlanErrors so a
	// detector bug reads as "this detector failed, its types are incomplete" —
	// never as a silent "0 candidates".
	DetectorErrors []evidence.DetectorError
	// DisabledTypes is the type switch actually applied this run (from
	// secguard.toml [disabled_types], validated against the registry). These
	// types produced no candidates and must not be reported as "unknown".
	DisabledTypes []string
	// SkippedDetectors is the detector switch actually applied this run (from
	// secguard.toml [scan] skip_detectors / --skip-detectors, validated against
	// the registered detectors). A skipped detector emitted no events, so the
	// types it feeds read as 0 candidates — this list is how that reads as a
	// switch, never as clean code.
	SkippedDetectors []string
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
// empty) list to override them. excludePaths are directory paths (from
// secguard.toml [exclude] paths) pruned during the index walk, resolved against
// absPath; nil/empty prunes nothing by path.
func runPipeline(ctx context.Context, store db.Store, logger *log.Logger, absPath string, excludeDirs []string, excludePaths []string) (*pipelineOutcome, error) {
	// Validate the static vuln-type registry (spec + filter chain) BEFORE the
	// expensive index/graph/detector phases. A registry typo that would otherwise
	// surface only as a per-type Plan failure after a long scan now fails the run
	// immediately, at zero cost.
	if err := planner.ValidateRegistry(); err != nil {
		return nil, fmt.Errorf("planner registry: %w", err)
	}

	p := parser.NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(config.Load().Scan.MaxCachedTrees)

	var timings pipelineTimings

	idx := indexer.NewIndexer(store, logger)
	if excludeDirs != nil {
		idx.SetExcludeDirs(excludeDirs)
	}
	idx.SetExcludePaths(excludePaths)
	idx.SetValidVulnTypes(planner.AllVulnTypes())

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

	// Build a shared read-only snapshot of all indexed functions and files once,
	// and inject it into ctx so every graph builder and detector reads from one
	// snapshot instead of each re-querying ListFunctions + ListFiles +
	// per-file GetFileByID (70+ redundant full-table scans on large repos).
	repoFuncs, err := store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list functions for repo index: %w", err)
	}
	repoFiles, err := store.ListFiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list files for repo index: %w", err)
	}
	ctx = graph.WithRepoIndex(ctx, graph.NewRepoIndex(repoFuncs, repoFiles))

	graphStart := time.Now()

	// Function-pointer slot -> target writes run SEQUENTIALLY before the parallel
	// builders: CallGraphBuilder and InterprocBuilder both consume the resolved
	// slots for indirect-call resolution (GAP-02). `[graph] indirect_call_resolution
	// = false` disables the pass (a deployment that proves the ops table is never
	// indirect can skip the traversal).
	if config.Load().IndirectCallResolutionEnabled() {
		if err := graph.NewFuncPtrWriteBuilder(store, p, logger).Build(ctx); err != nil {
			return nil, fmt.Errorf("func ptr writes: %w", err)
		}
	}

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
	builderSem := make(chan struct{}, config.Load().GraphBuildersConcurrencyOr(len(builders)))

	var memMon *MemoryMonitor
	if cfg := config.Load(); cfg.Scan.MemoryPressureEnabled && cfg.Scan.MemoryHighWatermarkMB > 0 {
		memMon = NewMemoryMonitor(int64(cfg.Scan.MemoryHighWatermarkMB)*1024*1024,
			int64(cfg.Scan.MemoryLowWatermarkMB)*1024*1024)
		memMon.Start(2*time.Second, logger)
		defer memMon.Stop()
	}

	for _, b := range builders {
		bwg.Add(1)
		go func(b builderTask) {
			defer bwg.Done()
			defer func() {
				if r := recover(); r != nil {
					bErrCh <- fmt.Errorf("%s panicked: %v", b.name, r)
				}
			}()
			for memMon != nil && memMon.Pressured() {
				time.Sleep(100 * time.Millisecond)
			}
			builderSem <- struct{}{}
			defer func() { <-builderSem }()
			if err := b.fn(ctx); err != nil {
				bErrCh <- fmt.Errorf("%s: %w", b.name, err)
			}
		}(b)
	}
	bwg.Wait()
	close(bErrCh)
	var errs []error
	for err := range bErrCh {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("graph build failed: %w", errors.Join(errs...))
	}
	timings.GraphMs = time.Since(graphStart).Milliseconds()
	logger.Info("phase timing", "phase", "graph_builders_parallel", "elapsed_ms", timings.GraphMs)

	if err := store.ClearSecurityEvents(ctx); err != nil {
		return nil, fmt.Errorf("clear security events: %w", err)
	}

	// Share one statement-CFG cache across the detector and plan stages: a
	// function's CFG is built at most once per scan, instead of once per
	// consuming detector plus once per consuming filter (the 8-12x rebuild
	// overhead this Phase removes).
	sharedCFGCache := graph.NewCFGCache()
	sharedCFGCache.MaxEntries = config.Load().Scan.CFGCacheMaxEntries
	sharedCFGCache.MaxTotalCFGNodes = config.Load().Scan.CFGCacheMaxTotalNodes

	// Build the per-scan interprocedural alias graph once and share it via
	// ctx with both stages. The current skeleton covers function-local
	// shapes; cross-function return/parameter/global aliasing is a follow-up.
	aliasGraph, aliasErr := graph.BuildInterproceduralAlias(ctx, store, p)
	if aliasErr != nil {
		logger.Warn("alias graph build degraded", "err", aliasErr)
		aliasGraph = graph.NewAliasGraph()
	}
	ctx = graph.WithAliasGraph(ctx, aliasGraph)

	// Validate the detector skip switch against the registry BEFORE running: an
	// unknown name is warned and dropped (a typo must not silently skip nothing
	// while the user believes a slow stage is off).
	skipSet := config.Load().SkipDetectorSet()
	knownDetectors := map[string]bool{}
	for _, name := range evidence.DetectorNames() {
		knownDetectors[name] = true
	}
	var skippedDetectors []string
	for name := range skipSet {
		if !knownDetectors[name] {
			logger.Warn("skip-detectors name is not a registered detector, ignoring", "detector", name)
			delete(skipSet, name)
			continue
		}
		skippedDetectors = append(skippedDetectors, name)
	}
	sort.Strings(skippedDetectors)

	detStart := time.Now()
	detectorErrors := evidence.RunAllDetectorsWithSkip(ctx, store, p, logger, sharedCFGCache, skipSet)
	timings.DetectorsMs = time.Since(detStart).Milliseconds()
	if len(skippedDetectors) > 0 {
		logger.Info("phase timing", "phase", "detectors_total", "elapsed_ms", timings.DetectorsMs,
			"skipped", skippedDetectors)
	} else {
		logger.Info("phase timing", "phase", "detectors_total", "elapsed_ms", timings.DetectorsMs)
	}
	if b, h, e, n, tn := sharedCFGCache.StatsFull(); b+h > 0 {
		logger.Info("cfg cache stats after detectors", "builds", b, "hits", h, "evictions", e, "entries", n, "total_nodes", tn)
	}

	// Backfill a function_summary row for every indexed function, so the
	// coverage acceptance (≥90%) holds and richer per-function contract facts
	// (outparam/release/return-semantics) have a row to layer onto. Runs once per
	// scan, after the null-source detector has seeded its literal-`return NULL`
	// witnesses, and before the plan stage consumes summaries.
	if produced, serr := planner.EnsureFunctionSummaries(ctx, store); serr != nil {
		return nil, fmt.Errorf("produce function summaries: %w", serr)
	} else if produced > 0 && logger != nil {
		logger.Info("function summary backfill", "produced", produced)
	}

	// Apply the type switch at the SOURCE: a disabled type is dropped from the
	// plan loop, so it produces no candidates and the AI agent's skills never
	// receive it. Unknown names are warned and dropped (a typo must not silently
	// disable the wrong type nor crash the run).
	disabledSet := config.Load().DisabledTypeSet()
	for name := range disabledSet {
		if _, err := planner.GetVulnTypeSpec(name); err != nil {
			logger.Warn("disabled type is not a registered vulnerability type, ignoring", "type", name)
			delete(disabledSet, name)
		}
	}
	var disabledTypes []string
	for name := range disabledSet {
		disabledTypes = append(disabledTypes, name)
	}
	sort.Strings(disabledTypes)

	vulnTypes := planner.ActiveVulnTypes(disabledSet)
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
	// shared parser is internally synchronized). The Planner also receives the
	// shared CFG cache so plan-stage filters hit the detector-stage builds.
	pl := planner.NewPlannerWithCache(store, p, logger, sharedCFGCache)

	// The interprocedural taint summary is candidate-set-independent and shared by
	// injection / path-traversal / format-string / integer-overflow. Compute it
	// once, in the background, while the per-type goroutines start: the types that
	// do not consume it run immediately, and only the four taint consumers wait for
	// it (they would have blocked on the same cache mutex anyway). This is what
	// gives the summary its OWN timing line instead of being reported four times
	// as "the plan time" of whichever type reached the cache first — while still
	// overlapping its cost with the other types' work, so the plan phase cannot get
	// slower than before.
	//
	// The prewarm is skipped when no taint type has a seed event: those types never
	// run their filter chain, so they would pay the whole-tree fixpoints and use
	// none of the result.
	var taintTypeSet map[string]bool
	summaryReady := make(chan struct{})
	if taintTypes := planner.TaintSummaryTypes(vulnTypes); len(taintTypes) > 0 {
		taintTypeSet = make(map[string]bool, len(taintTypes))
		for _, name := range taintTypes {
			taintTypeSet[name] = true
		}
		seeded, serr := pl.AnySeedCandidate(ctx, taintTypes)
		if serr != nil {
			logger.Warn("plan shared taint summary prewarm probe failed", "err", serr)
		}
		if seeded {
			go func() {
				// Close LAST (LIFO): the waiting taint types must be released even
				// if the summary computation panics.
				defer close(summaryReady)
				defer func() {
					if r := recover(); r != nil {
						logger.Warn("plan shared taint summary prewarm panicked", "panic", r)
					}
				}()
				summaryStart := time.Now()
				if err := pl.PrewarmTaintSummary(ctx); err != nil {
					// Fail-open: the filter recomputes and keeps candidates on error.
					logger.Warn("plan shared taint summary prewarm failed", "err", err)
				}
				logger.Info("phase timing", "phase", "plan_shared_taint_summary", "elapsed_ms", time.Since(summaryStart).Milliseconds())
			}()
		} else {
			close(summaryReady)
		}
	} else {
		close(summaryReady)
	}

	planConcurrency := config.Load().PlanConcurrencyOr(8)
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
			// A taint-consuming type waits for the shared summary BEFORE taking a
			// concurrency slot, so queued non-taint types are never starved by
			// goroutines that would only block on the summary.
			if taintTypeSet[vt] {
				<-summaryReady
			}
			for memMon != nil && memMon.Pressured() {
				time.Sleep(100 * time.Millisecond)
			}
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
	if b, h, e, n, tn := sharedCFGCache.StatsFull(); b+h > 0 {
		logger.Info("cfg cache stats after plan", "builds", b, "hits", h, "evictions", e, "entries", n, "total_nodes", tn)
	}

	return &pipelineOutcome{
		Index:            indexResult,
		Plans:            plans,
		PlanErrors:       planErrors,
		DetectorErrors:   detectorErrors,
		DisabledTypes:    disabledTypes,
		SkippedDetectors: skippedDetectors,
		Timings:          timings,
	}, nil
}
