package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kongan/secguard-lite/internal/evidence"
	"github.com/kongan/secguard-lite/internal/graph"
	"github.com/kongan/secguard-lite/internal/indexer"
	"github.com/kongan/secguard-lite/internal/parser"
)

func runIndexCmd(ctx context.Context, args []string) int {
	dbPath, remaining := parseDBFlag(args)
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

	idx := indexer.NewIndexer(store, logger)
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

	WriteJSON(map[string]interface{}{
		"status":            "ok",
		"files_indexed":     result.FilesIndexed,
		"functions_indexed": result.FunctionsIndexed,
		"files_skipped":     result.FilesSkipped,
	})
	return 0
}
