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

	dbPath = resolveDBPath(dbExplicit, dbPath, absPath)

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
	cgBuilder.Build(ctx)

	dfBuilder := graph.NewDataFlowBuilder(store, p, logger)
	dfBuilder.Build(ctx)

	store.ClearSecurityEvents(ctx)

	evidence.RunAllDetectors(ctx, store, p, logger)

	funcs, _ := store.ListFunctions(ctx)
	WriteJSON(map[string]interface{}{
		"status":             "ok",
		"files_indexed":      result.FilesIndexed,
		"functions_indexed":  result.FunctionsIndexed,
		"functions_in_index": len(funcs),
		"files_skipped":      result.FilesSkipped,
	})
	return 0
}
