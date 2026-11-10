package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DannyAn/secguard-clang/internal/concurrency"
	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
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
// applyScanMemoryLimits installs the Go-runtime memory controls shared by the
// full scan pipeline and the single-type `plan` command (the same OOM-sensitive
// convergence filters run in both). An explicit [scan] go_mem_limit_mb wins; a
// deliberate smaller GOMEMLIMIT is not enlarged by the cgroup-derived default.
func applyScanMemoryLimits() {
	if cfg := config.Load(); cfg.Scan.GoMemLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.Scan.GoMemLimitMB) * 1024 * 1024)
	} else if limit := config.DetectCgroupMemoryLimit(); limit > 0 {
		// No explicit go_mem_limit_mb: derive the Go soft memory limit from the
		// cgroup ceiling (85% leaves GC headroom). This turns "OOM-killed at the
		// cgroup limit" into "GC reclaims before SIGKILL", the production-safety
		// default that used to require a hand-written secguard.toml.
		//
		// Do not override a deliberate GOMEMLIMIT env (or any other finite limit
		// already installed): only replace the default "no limit". SetMemoryLimit
		// returns the previous limit, so set the derived value and restore a
		// smaller explicit one.
		derived := limit * 85 / 100
		if prev := debug.SetMemoryLimit(derived); prev != math.MaxInt64 && prev < derived {
			debug.SetMemoryLimit(prev)
		}
	}
	if cfg := config.Load(); cfg.Scan.GoGCPercent > 0 {
		debug.SetGCPercent(cfg.Scan.GoGCPercent)
	}
}

func runPipeline(ctx context.Context, store db.Store, logger *log.Logger, absPath string, excludeDirs []string, excludePaths []string) (*pipelineOutcome, error) {
	// Validate the static vuln-type registry (spec + filter chain) BEFORE the
	// expensive index/graph/detector phases. A registry typo that would otherwise
	// surface only as a per-type Plan failure after a long scan now fails the run
	// immediately, at zero cost.
	if err := planner.ValidateRegistry(); err != nil {
		return nil, fmt.Errorf("planner registry: %w", err)
	}
	applyScanMemoryLimits()

	p := parser.NewParser()
	defer func() {
		p.CloseAll()
		if leaks := p.LeakedTrees(); len(leaks) > 0 {
			logger.Warn("parser: trees still borrowed at scan end", "count", len(leaks), "details", leaks)
		}
		if live := planner.LiveFileParseCaches(); len(live) > 0 {
			logger.Warn("planner: fileParseCache(s) not closed", "count", len(live), "creators", live)
		}
	}()
	p.SetMaxCachedTrees(config.Load().Scan.MaxCachedTrees)
	if cfg := config.Load(); cfg.Scan.MaxCachedTrees <= 0 {
		logger.Warn("AST cache is unbounded (max_cached_trees=0); set [scan] max_cached_trees to bound peak RSS on large repos")
	}

	var timings pipelineTimings

	idx := indexer.NewIndexer(store, logger)
	defer idx.Close()
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
	logPhaseResources(logger, "index", p, nil)

	// Validate the detector skip switch against the registry BEFORE any
	// expensive stage. Detector names are snake_case; `secguard types` prints
	// kebab-case VULN types, so a kebab spelling is normalized to its snake
	// equivalent (issue #253: `--skip-detectors integer-overflow` used to be
	// silently ignored and the scan crashed again in the very detector the
	// user meant to turn off). An unknown name is a HARD failure listing the
	// legal names — warn-and-continue leaves the user believing a stage is off
	// while it runs.
	skipSet := config.Load().SkipDetectorSet()
	knownDetectors := map[string]bool{}
	for _, name := range evidence.DetectorNames() {
		knownDetectors[name] = true
	}
	normalizedSkip := make(map[string]bool, len(skipSet))
	var unknownSkips []string
	for name := range skipSet {
		normalized := strings.ReplaceAll(name, "-", "_")
		if !knownDetectors[normalized] {
			unknownSkips = append(unknownSkips, name)
			continue
		}
		normalizedSkip[normalized] = true
	}
	if len(unknownSkips) > 0 {
		sort.Strings(unknownSkips)
		return nil, fmt.Errorf("skip-detectors names %v are not registered detectors (registered: %s)",
			unknownSkips, strings.Join(evidence.DetectorNames(), ", "))
	}
	skipSet = normalizedSkip
	var skippedDetectors []string
	for name := range skipSet {
		skippedDetectors = append(skippedDetectors, name)
	}
	sort.Strings(skippedDetectors)

	// Reuse is split in two independent halves so a detector failure never
	// forces a graph rebuild, and a graph inconsistency never reuses events:
	//   graphReusable     — no file change, the graph-input fingerprint matches,
	//                       and the last graph build COMPLETED (invalidated at
	//                       the START of every rebuild, and recorded complete
	//                       immediately after the builders finish, BEFORE the
	//                       detectors run — a detector-stage crash must not
	//                       force the next scan to rebuild a valid graph;
	//                       issue #253 wasted two full rebuilds that way).
	//   detectorsReusable — graphReusable AND every detector required this run
	//                       is in the last completed-detector set. A detector
	//                       that failed last time is therefore always re-run.
	// The skip set is deliberately NOT part of the graph fingerprint: skipping
	// a detector changes no AST, so `--skip-detectors` must not invalidate the
	// graph. A reduced skip set can never masquerade as a full detector run
	// either — detectorsComplete requires every newly-required detector in the
	// recorded done set.
	fingerprint := reuseFingerprint(absPath, excludeDirs, excludePaths)
	graphReusable := indexResult.FilesChanged == 0 &&
		reuseFingerprintUnchanged(ctx, store, fingerprint) &&
		graphBuildComplete(ctx, store)
	detectorsReusable := graphReusable && detectorsComplete(ctx, store, skipSet)
	if detectorsReusable {
		logger.Info("phase skipped", "phase", "graph+detectors", "reason", "no file/config changed and prior graph+detectors completed")
	} else if graphReusable {
		logger.Info("phase skipped", "phase", "graph", "reason", "graph reusable; re-running detectors to close a prior incomplete detector set")
	}
	var memMon *MemoryMonitor
	var detectorErrors []evidence.DetectorError

	// The semantic graph is rebuilt from scratch every run (there is no
	// incremental graph update), so clear the previous run's nodes/edges first.
	// The completion flag is invalidated BEFORE the rebuild starts: a crash or
	// builder failure mid-rebuild must never leave a half-built graph reading
	// as complete on the next scan.
	if !graphReusable {
		if err := store.SetMeta(ctx, "graph_build_complete", "false"); err != nil {
			return nil, fmt.Errorf("invalidate graph completion: %w", err)
		}
		if err := store.ClearGraph(ctx); err != nil {
			return nil, fmt.Errorf("clear graph: %w", err)
		}
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
	repoFacts := graph.RepoFacts{}
	if vars, verr := store.ListFileScopeVariables(ctx); verr == nil {
		repoFacts.FileScope = vars
		repoFacts.FileScopeOK = true
	} else {
		logger.Warn("repo index: file-scope facts load failed; builders will query per stage", "err", verr)
	}
	if writes, werr := store.ListFuncPtrWrites(ctx); werr == nil {
		repoFacts.FuncPtrWrites = writes
		repoFacts.FuncPtrWritesOK = true
	} else {
		logger.Warn("repo index: func-ptr facts load failed; builders will query per stage", "err", werr)
	}
	ctx = graph.WithRepoIndex(ctx, graph.NewRepoIndexWithFacts(repoFuncs, repoFiles, repoFacts))

	if !graphReusable {
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

		if cfg := config.Load(); cfg.Scan.MemoryPressureEnabled {
			highMB := cfg.Scan.MemoryHighWatermarkMB
			lowMB := cfg.Scan.MemoryLowWatermarkMB
			if highMB == 0 {
				// Backpressure opted in without a watermark: derive it from the
				// cgroup ceiling so a containerized scan does not have to hand-compute
				// the threshold. 70% high / 52.5% low leaves headroom for the other
				// resident processes sharing the cgroup.
				if limit := config.DetectCgroupMemoryLimit(); limit > 0 {
					// Apply the 70% in bytes before the MB conversion so a small
					// ceiling still yields a non-zero watermark instead of truncating
					// to zero on the MB division first.
					highMB = int(limit * 7 / 10 / (1024 * 1024))
					lowMB = highMB * 3 / 4
				}
			}
			if highMB > 0 {
				memMon = NewMemoryMonitor(int64(highMB)*1024*1024,
					int64(lowMB)*1024*1024)
				memMon.Start(2*time.Second, logger)
				defer memMon.Stop()
			}
		}
		builderGate := concurrency.NewGate(config.Load().GraphBuildersConcurrencyOr(len(builders)),
			func() bool { return memMon != nil && memMon.Pressured() })

		for _, b := range builders {
			bwg.Add(1)
			go func(b builderTask) {
				defer bwg.Done()
				defer func() {
					if r := recover(); r != nil {
						bErrCh <- fmt.Errorf("%s panicked: %v", b.name, r)
					}
				}()
				if !builderGate.Acquire(ctx) {
					bErrCh <- fmt.Errorf("%s: canceled while waiting for memory capacity", b.name)
					return
				}
				defer builderGate.Release()
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
		logPhaseResources(logger, "graph", p, nil)

		// Record graph completion NOW, before the detector stage: the graph is
		// valid at this point, and a later detector crash (or an unrecoverable
		// runtime fatal) must leave it reusable for the next scan.
		if err := store.SetMeta(ctx, "graph_build_complete", "true"); err != nil {
			logger.Warn("failed to record graph build complete", "error", err)
		}
	}

	// Share one statement-CFG cache across the detector and plan stages: a
	// function's CFG is built at most once per scan, instead of once per
	// consuming detector plus once per consuming filter (the 8-12x rebuild
	// overhead this Phase removes).
	sharedCFGCache := graph.NewCFGCache()
	sharedCFGCache.MaxEntries = config.Load().Scan.CFGCacheMaxEntries
	sharedCFGCache.MaxTotalCFGNodes = config.Load().Scan.CFGCacheMaxTotalNodes
	// Release every CFG entry's AST borrow before the parser's CloseAll runs;
	// otherwise the CFG cache itself looks like a leaked borrow at scan end.
	// Registered after the parser defer, so LIFO runs this first.
	defer sharedCFGCache.Reset()

	// Build the per-scan interprocedural alias graph once and share it via
	// ctx with both stages. The current skeleton covers function-local
	// shapes; cross-function return/parameter/global aliasing is a follow-up.
	aliasGraph, aliasErr := graph.BuildInterproceduralAlias(ctx, store, p)
	if aliasErr != nil {
		logger.Warn("alias graph build degraded", "err", aliasErr)
		aliasGraph = graph.NewAliasGraph()
	}
	ctx = graph.WithAliasGraph(ctx, aliasGraph)

	// Build the per-scan tree-wide repository facts (struct layouts, global
	// arrays, capacity macros) once and share via ctx with both the detector
	// and planner stages. Layout census uses default ABI (LP64) +
	// assumed_default_abi provenance; per-TU compile_commands wiring is a
	// follow-up. A build failure is non-fatal: consumers fall back to nil.
	facts, factsErr := repofacts.Build(ctx, store, p, logger)
	if factsErr != nil {
		logger.Warn("repofacts build degraded", "err", factsErr)
		facts = nil
	}
	ctx = repofacts.WithFacts(ctx, facts)

	// Events are cleared whenever detectors re-run — including the
	// graph-reusable-but-detectors-incomplete path — so a re-run never mixes
	// stale events with fresh ones (and never duplicates them).
	if !detectorsReusable {
		if err := store.ClearSecurityEvents(ctx); err != nil {
			return nil, fmt.Errorf("clear security events: %w", err)
		}
		detStart := time.Now()
		evidence.SetEventBatchSize(config.Load().Scan.EventBatchSize)
		evidence.SetDetectorConcurrency(config.Load().DetectorConcurrencyOr(8))
		evidence.SetDetectorThrottle(func() bool { return memMon != nil && memMon.Pressured() })
		detectorErrors = evidence.RunAllDetectorsWithSkip(ctx, store, p, logger, sharedCFGCache, skipSet)
		if n := evidence.EventFlushFailures(); n > 0 {
			detectorErrors = append(detectorErrors, evidence.DetectorError{
				Detector: "event_batch",
				Err:      fmt.Errorf("%d event batch flush(es) failed; those events were lost", n),
			})
		}
		timings.DetectorsMs = time.Since(detStart).Milliseconds()
		if len(skippedDetectors) > 0 {
			logger.Info("phase timing", "phase", "detectors_total", "elapsed_ms", timings.DetectorsMs,
				"skipped", skippedDetectors)
		} else {
			logger.Info("phase timing", "phase", "detectors_total", "elapsed_ms", timings.DetectorsMs)
		}
		logPhaseResources(logger, "detectors", p, sharedCFGCache)
	}

	// Record the pipeline meta that gates the next run's reuse check.
	// graph_build_complete=true means the graph itself is valid (a builder
	// error returned early above and never reaches here). detectors_done is the
	// set of detectors that COMPLETED this run: a failed detector is absent, so
	// the next scan re-runs it instead of reading its types as "0 candidates".
	// An event-batch flush failure invalidates the whole set (events were lost
	// and there is no per-detector attribution for the loss).
	if err := store.SetMeta(ctx, "config_checksum", config.ConfigChecksum()); err != nil {
		logger.Warn("failed to record config checksum", "error", err)
	}
	if err := store.SetMeta(ctx, "reuse_fingerprint", fingerprint); err != nil {
		logger.Warn("failed to record reuse fingerprint", "error", err)
	}

	if !detectorsReusable {
		if n := evidence.EventFlushFailures(); n == 0 {
			done := detectorDoneSet(skipSet, detectorErrors)
			if err := store.SetMeta(ctx, "detectors_done", strings.Join(done, ",")); err != nil {
				logger.Warn("failed to record completed detectors", "error", err)
			}
		} else if err := store.SetMeta(ctx, "detectors_done", ""); err != nil {
			logger.Warn("failed to invalidate completed detectors", "error", err)
		}
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

	// The [type-filter] positional argument (`scan <path> <type>[,<type>...]`)
	// narrows the plan stage to an allow-list. A typo or an all-disabled filter
	// must fail, not silently plan zero types (a zero-plan scan would look
	// "clean" while producing no candidates). runScanCmd validates this before
	// the expensive stages; re-check here for every other pipeline caller.
	typeFilter := config.Load().TypeFilterSet()
	for name := range typeFilter {
		if _, err := planner.GetVulnTypeSpec(name); err != nil {
			return nil, fmt.Errorf("type-filter names unknown vulnerability type %q: %w", name, err)
		}
	}
	vulnTypes := planner.TypeFilteredActiveVulnTypes(disabledSet, typeFilter)
	if len(typeFilter) > 0 && len(vulnTypes) == 0 {
		return nil, fmt.Errorf("type-filter matched no enabled vulnerability type (every requested type is disabled by [disabled_types])")
	}
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
	planGate := concurrency.NewGate(planConcurrency,
		func() bool { return memMon != nil && memMon.Pressured() })
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
			if !planGate.Acquire(ctx) {
				planErrMu.Lock()
				planErrors[vt] = "canceled while waiting for memory capacity"
				planErrMu.Unlock()
				return
			}
			defer planGate.Release()
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
	logPhaseResources(logger, "plan", p, sharedCFGCache)

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

// graphExists reports whether the DB has any graph edges from a prior run.
// It is the reuse gate for skipping the graph+detector rebuild when no source
// file changed since the last index/scan.
func graphExists(ctx context.Context, store db.Store) bool {
	var exists bool
	err := store.DB().QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM graph_edges)").Scan(&exists)
	return err == nil && exists
}

// eventsExist reports whether the DB has any security events from a prior run.
func eventsExist(ctx context.Context, store db.Store) bool {
	var exists bool
	err := store.DB().QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM security_events)").Scan(&exists)
	return err == nil && exists
}

// reuseFingerprint is the complete identity of the GRAPH inputs: the config
// checksum PLUS everything that used to bypass it — the tool version, the
// registered detector set (a new detector may need graph facts its predecessor
// never built), the exclusion lists, and compile_commands (its -D/-I flags
// change the AST the graph is built from). The skip-detectors set is NOT an
// input: it gates the detector stage only, which has its own completeness
// check (detectorsComplete). Any change in a real graph input must invalidate
// the reuse, or a scan keeps reporting verdicts derived from a different
// analyzer configuration.
func reuseFingerprint(absPath string, excludeDirs, excludePaths []string) string {
	h := sha256.New()
	io.WriteString(h, config.ConfigChecksum())
	io.WriteString(h, "|v:"+Version)
	io.WriteString(h, "|det:"+strings.Join(evidence.DetectorNames(), ","))
	io.WriteString(h, "|exd:"+strings.Join(excludeDirs, ","))
	io.WriteString(h, "|exp:"+strings.Join(excludePaths, ","))
	ccPath := filepath.Join(absPath, "compile_commands.json")
	if data, err := os.ReadFile(ccPath); err == nil {
		h.Write([]byte("|cc:"))
		h.Write(data)
	} else {
		io.WriteString(h, "|cc:none")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// reuseFingerprintUnchanged reports whether the recorded fingerprint equals
// this run's. A missing meta row (first run, or a pre-fingerprint DB) returns
// false so the build runs once and records it.
func reuseFingerprintUnchanged(ctx context.Context, store db.Store, fingerprint string) bool {
	stored, ok, err := store.GetMeta(ctx, "reuse_fingerprint")
	if err != nil || !ok {
		return false
	}
	return stored == fingerprint
}

// detectorsComplete reports whether every detector required this run is in the
// completed-detector set recorded at the last detectors run. An empty recorded
// set (event loss, or a run that pre-dates the marker) is incomplete, so the
// detectors stage re-runs instead of reusing a partial event stream.
func detectorsComplete(ctx context.Context, store db.Store, skipSet map[string]bool) bool {
	required := requiredDetectors(skipSet)
	if len(required) == 0 {
		return true
	}
	stored, ok, err := store.GetMeta(ctx, "detectors_done")
	if err != nil || !ok || stored == "" {
		return false
	}
	done := map[string]bool{}
	for _, name := range strings.Split(stored, ",") {
		done[name] = true
	}
	for _, name := range required {
		if !done[name] {
			return false
		}
	}
	return true
}

func requiredDetectors(skipSet map[string]bool) []string {
	var out []string
	for _, name := range evidence.DetectorNames() {
		if !skipSet[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// detectorDoneSet is the required set minus the detectors that failed this run
// (the special "event_batch" entry is not a detector name and is excluded).
func detectorDoneSet(skipSet map[string]bool, errs []evidence.DetectorError) []string {
	failed := map[string]bool{}
	for _, e := range errs {
		failed[e.Detector] = true
	}
	var out []string
	for _, name := range requiredDetectors(skipSet) {
		if !failed[name] {
			out = append(out, name)
		}
	}
	return out
}

// configChecksumUnchanged reports whether the current config file's checksum
// matches the one recorded at the last graph+detector build. A missing meta
// row (first run, or pre-this-feature DB) returns false so the build runs once
// and records the checksum for future runs.
func configChecksumUnchanged(ctx context.Context, store db.Store) bool {
	stored, ok, err := store.GetMeta(ctx, "config_checksum")
	if err != nil || !ok {
		return false
	}
	return stored == config.ConfigChecksum()
}

// graphBuildComplete reports whether the last graph+detector build recorded
// graph_build_complete="true". A missing meta row returns false so the build
// runs once and records completion for future runs.
func graphBuildComplete(ctx context.Context, store db.Store) bool {
	val, ok, err := store.GetMeta(ctx, "graph_build_complete")
	if err != nil || !ok {
		return false
	}
	return val == "true"
}
