//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestGlobalInvariants_DivideByZero(t *testing.T) {
	src := `#include <stdlib.h>

static int g_count = 0;

void register_item(int n) {
    if (n == 0) return;
    g_count = n;
}

int fp_global_after_guard(void) {
    return 100 / g_count;
}

int tp_local_zero(void) {
    int d = 0;
    return 100 / d;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "inv.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewDivideByZeroDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if kept["fp_global_after_guard"] {
		t.Errorf("fp_global_after_guard (g_count proven non-zero by register_item guard) should be suppressed, got %v", candidateNames(result))
	}
	if !kept["tp_local_zero"] {
		t.Errorf("tp_local_zero (d is literal 0) should be kept, got %v", candidateNames(result))
	}
}

func TestGlobalInvariants_BackfillDefault(t *testing.T) {
	src := `#include <stdlib.h>

static int g_size = 0;

void init_size(int s) {
    if (s == 0) s = 1;
    g_size = s;
}

int fp_backfill(void) {
    return 256 / g_size;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "backfill.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewDivideByZeroDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if kept["fp_backfill"] {
		t.Errorf("fp_backfill (g_size backfilled with default 1) should be suppressed, got %v", candidateNames(result))
	}
}
