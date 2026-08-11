package evidence

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestIntegration_FullScanPipeline(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	benchmarkDir := filepath.Join("..", "..", "testdata")
	entries, err := os.ReadDir(benchmarkDir)
	if err != nil {
		t.Fatalf("failed to read testdata dir: %v", err)
	}

	cFiles := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) == ".c" && len(name) > 2 && name[0] == 't' && name[1] == 'c' {
			cFiles = append(cFiles, filepath.Join(benchmarkDir, name))
		}
	}
	if len(cFiles) < 17 {
		t.Fatalf("expected at least 17 test fixtures, found %d", len(cFiles))
	}

	idx := indexer.NewIndexer(store, logger)
	for _, f := range cFiles {
		if _, err := idx.Index(ctx, f); err != nil {
			t.Fatalf("index failed for %s: %v", f, err)
		}
	}

	cgBuilder := graph.NewCallGraphBuilder(store, p, logger)
	cgBuilder.Build(ctx)

	dfBuilder := graph.NewDataFlowBuilder(store, p, logger)
	dfBuilder.Build(ctx)

	NewNullSourceDetector(store, p, logger).Detect(ctx)
	NewDereferenceDetector(store, p, logger).Detect(ctx)
	NewNullGuardDetector(store, p, logger).Detect(ctx)
	NewInterproceduralDetector(store, p, logger).Detect(ctx)
	NewMemoryLeakDetector(store, p, logger).Detect(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)
	NewInjectionDetector(store, p, logger).Detect(ctx)
	NewResourceLeakDetector(store, p, logger).Detect(ctx)
	NewUninitVariableDetector(store, p, logger).Detect(ctx)

	expectedEvents := map[string]int{
		"NULL_VALUE":       1,
		"DEREFERENCE":      1,
		"MEMORY_ALLOC":     1,
		"RESOURCE_ACQUIRE": 1,
		"VALUE_USE":        1,
	}
	for eventType, minCount := range expectedEvents {
		events, err := store.ListEventsByType(ctx, eventType)
		if err != nil {
			t.Fatalf("failed to list %s events: %v", eventType, err)
		}
		if len(events) < minCount {
			t.Errorf("expected at least %d %s events, got %d", minCount, eventType, len(events))
		}
	}

	pl := planner.NewPlanner(store, nil, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if result.CandidateCount() == 0 {
		t.Error("expected at least 1 null-deref candidate from full scan")
	}

	funcs, _ := store.ListFunctions(ctx)
	if len(funcs) < 20 {
		t.Errorf("expected at least 20 indexed functions, got %d", len(funcs))
	}

	indexedFiles, _ := store.ListFiles(ctx)
	if len(indexedFiles) < 17 {
		t.Errorf("expected at least 17 indexed files, got %d", len(indexedFiles))
	}
}
