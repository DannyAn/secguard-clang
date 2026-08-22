package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/parser"
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
	result, err := idx.Index(ctx, absPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("index failed: %v", err))
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

	if err := evidence.RunAllDetectors(ctx, store, p, logger); err != nil {
		WriteErrorJSON(fmt.Sprintf("detectors failed: %v", err))
		return 1
	}

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list functions: %v", err))
		return 1
	}
	WriteJSON(map[string]interface{}{
		"status":             "ok",
		"files_indexed":      result.FilesIndexed,
		"functions_indexed":  result.FunctionsIndexed,
		"functions_in_index": len(funcs),
		"files_skipped":      result.FilesSkipped,
	})
	return 0
}
