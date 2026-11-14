package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DannyAn/secguard-clang/internal/allocdiscover"
	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

func runIndexCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	excludeDirs, hasExclude := parseExcludeFlag(remaining)
	remaining = removeFlag(remaining, "exclude")
	if len(remaining) == 0 {
		WriteErrorJSON("index requires a path argument")
		return 1
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

	// DB lives at the project root (cwd), not under the index target, so
	// `secguard index ./src` and `secguard plan <type>` resolve the same DB.
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

	logger := defaultLogger()
	p := parser.NewParser()
	defer p.CloseAll()

	idx := indexer.NewIndexer(store, logger)
	if hasExclude {
		idx.SetExcludeDirs(excludeDirs)
	}
	idx.SetExcludePaths(config.Load().ExcludePaths())
	idx.SetValidVulnTypes(planner.AllVulnTypes())
	result, err := idx.Index(ctx, absPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("index failed: %v", err))
		return 1
	}

	// Same as scan: the graph builders rebuild the full graph every run, so clear
	// the previous graph (and its dead variables rows) before rebuilding.
	if err := store.ClearGraph(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to clear graph: %v", err))
		return 1
	}

	cgBuilder := graph.NewCallGraphBuilder(store, p, logger)
	if _, err := cgBuilder.Build(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("call graph build failed: %v", err))
		return 1
	}

	dfBuilder := graph.NewDataFlowBuilder(store, p, logger)
	if _, err := dfBuilder.Build(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("data flow build failed: %v", err))
		return 1
	}

	aliasBuilder := graph.NewAliasBuilder(store, p, logger)
	if _, err := aliasBuilder.Build(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("alias build failed: %v", err))
		return 1
	}

	ownershipBuilder := graph.NewOwnershipBuilder(store, p, logger)
	if _, err := ownershipBuilder.Build(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("ownership build failed: %v", err))
		return 1
	}

	interprocBuilder := graph.NewInterprocBuilder(store, p, logger)
	if _, err := interprocBuilder.Build(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("interproc build failed: %v", err))
		return 1
	}

	lockOrderBuilder := graph.NewLockOrderBuilder(store, p, logger)
	if _, err := lockOrderBuilder.Build(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("lock-order build failed: %v", err))
		return 1
	}

	sharedAccessBuilder := graph.NewSharedAccessBuilder(store, p, logger)
	if _, err := sharedAccessBuilder.Build(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("shared-access build failed: %v", err))
		return 1
	}

	if err := store.ClearSecurityEvents(ctx); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to clear security events: %v", err))
		return 1
	}

	detectorErrors := evidence.RunAllDetectors(ctx, store, p, logger)
	// Event-batch flush failures are lost evidence with no per-detector
	// attribution; surface them as a detector error so the index command does
	// not report a clean status over a silently-dropped event batch (issue #275
	// P1-9).
	if n := evidence.EventFlushFailures(); n > 0 {
		detectorErrors = append(detectorErrors, evidence.DetectorError{
			Detector: "event_batch",
			Err:      fmt.Errorf("%d event batch flush(es) failed; those events were lost", n),
		})
	}
	detErrMap := map[string]string{}
	for _, de := range detectorErrors {
		detErrMap[de.Detector] = de.Err.Error()
	}

	// Record the pipeline meta so a subsequent `secguard scan` can skip the
	// graph+detector rebuild when no file/config changed. index always rebuilds
	// (it is an explicit command), so graph_build_complete is always "true"
	// here — a graph-builder error returns early above and never reaches this.
	if err := store.SetMeta(ctx, "config_checksum", config.ConfigChecksum()); err != nil {
		logger.Warn("failed to record config checksum", "error", err)
	}
	if err := store.SetMeta(ctx, "graph_build_complete", "true"); err != nil {
		logger.Warn("failed to record graph build complete", "error", err)
	}

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list functions: %v", err))
		return 1
	}
	status := "ok"
	exitCode := 0
	if len(detErrMap) > 0 {
		// A detector or event-batch failure means the evidence set is incomplete;
		// reading that as "ok" (exit 0) makes CI and the agent read missing
		// evidence as "clean". Report partial and fail so the caller re-runs.
		status = "partial"
		exitCode = 1
	}
	WriteJSON(map[string]interface{}{
		"status":             status,
		"files_indexed":      result.FilesIndexed,
		"functions_indexed":  result.FunctionsIndexed,
		"functions_scanned":  result.FunctionsScanned,
		"functions_in_index": len(funcs),
		"files_skipped":      result.FilesSkipped,
		"detector_errors":    detErrMap,
		"suggested_config":   writeSuggestedConfig(ctx, store, projectRoot),
	})
	return exitCode
}

// writeSuggestedConfig discovers project-specific allocator/deallocator names
// and writes them to <projectRoot>/.codeagent/secguard-clang/secguard.toml.suggested.
// It is best-effort and advisory: a failure or an existing file never fails the
// index, and secguard.toml itself is never touched. The returned string is the
// human-readable status surfaced in the index JSON.
func writeSuggestedConfig(ctx context.Context, store db.Store, projectRoot string) string {
	res, err := allocdiscover.Discover(ctx, store)
	if err != nil {
		return "error: " + err.Error()
	}
	path := report.SuggestedConfigPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "error: " + err.Error()
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return "skipped (already exists): " + path
		}
		return "error: " + err.Error()
	}
	// A partially written suggestion must not masquerade as a complete file: on
	// any write/sync/close failure remove it so a later index can retry instead
	// of reporting "skipped (already exists)" forever.
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := f.WriteString(res.Render()); err != nil {
		return "error: " + err.Error()
	}
	if err := f.Sync(); err != nil {
		return "error: " + err.Error()
	}
	if err := f.Close(); err != nil {
		return "error: " + err.Error()
	}
	ok = true
	return "written: " + path
}
