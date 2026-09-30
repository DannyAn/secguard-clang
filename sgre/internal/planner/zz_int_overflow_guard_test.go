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

func TestIntOverflow_OverflowCheckGuard(t *testing.T) {
	src := `#include <stdlib.h>

int get_count(void) { return 0; }
int get_size(void) { return 0; }

void fp_safe_mul(void) {
    int n = get_count();
    int sz = get_size();
    if (n > 1000 / sz) return;
    char *buf = malloc(n * sz);
    (void)buf;
}

void tp_no_check(void) {
    int n = get_count();
    int sz = get_size();
    char *buf = malloc(n * sz);
    (void)buf;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "overflow_check.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewIntegerOverflowDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "integer-overflow")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if kept["fp_safe_mul"] {
		t.Errorf("fp_safe_mul (overflow check guard) should be suppressed, got %v", candidateNames(result))
	}
	if !kept["tp_no_check"] {
		t.Errorf("tp_no_check (no overflow check) should be kept, got %v", candidateNames(result))
	}
}
