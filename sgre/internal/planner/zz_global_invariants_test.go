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
func TestGlobalInvariants_NonZeroSourceField(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

struct graph_info {
    uint32_t gran_time;
    uint32_t point_num;
};

uint32_t nlog_get_gran_time(int flag) {
    return 60;
}

void init_graph(struct graph_info *graph, int flag) {
    graph->gran_time = nlog_get_gran_time(flag);
}

uint32_t fp_field_from_func(struct graph_info *graph, uint32_t offset) {
    return offset / graph->gran_time;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "field.c")
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

	if kept["fp_field_from_func"] {
		t.Errorf("fp_field_from_func (graph->gran_time assigned from non-zero-returning nlog_get_gran_time) should be suppressed, got %v", candidateNames(result))
	}
}

func TestGlobalInvariants_ZeroInitNotSuppressed(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

static uint32_t g_thread_count = 0;

void init_threads(void) {
    g_thread_count = 4;
}

uint32_t tp_global_zero_init(uint32_t index) {
    return index % g_thread_count;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "global.c")
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

	if !kept["tp_global_zero_init"] {
		t.Errorf("tp_global_zero_init (g_thread_count is static-initialized to 0, so it can be zero before init_threads runs) should be kept, got %v", candidateNames(result))
	}
}

func TestGlobalInvariants_NonZeroInitSuppressed(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

static uint32_t g_buf_size = 64;

void resize(void) {
    g_buf_size = 128;
}

uint32_t fp_global_nonzero_init(uint32_t len) {
    return len / g_buf_size;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "global2.c")
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

	if kept["fp_global_nonzero_init"] {
		t.Errorf("fp_global_nonzero_init (g_buf_size has a non-zero initializer and only non-zero assignments) should be suppressed, got %v", candidateNames(result))
	}
}

func TestGlobalInvariants_NonZeroSourceMixed(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

struct graph_info {
    uint32_t gran_time;
};

uint32_t get_gran(void) {
    return 60;
}

void init_good(struct graph_info *g) {
    g->gran_time = get_gran();
}

void init_bad(struct graph_info *g, uint32_t x) {
    g->gran_time = x;
}

uint32_t tp_mixed_assign(struct graph_info *g, uint32_t offset) {
    return offset / g->gran_time;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.c")
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

	if !kept["tp_mixed_assign"] {
		t.Errorf("tp_mixed_assign (g->gran_time has an assignment from unknown source x, should NOT be suppressed) should be kept, got %v", candidateNames(result))
	}
}

func TestGlobalInvariants_LocalVarNotCrossFunction(t *testing.T) {
	src := `#include <stdlib.h>

int set_local(void) {
    int d = 5;
    return d;
}

int tp_local_divisor(int x) {
    int d = x;
    return 10 / d;   /* d is a local, possibly zero */
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "local.c")
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

	if !kept["tp_local_divisor"] {
		t.Errorf("tp_local_divisor (local d = x, possibly zero) should be kept — a same-named local d=5 in set_local must not mark d non-zero cross-function, got %v", candidateNames(result))
	}
}
