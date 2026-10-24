//go:build !nosqlite

package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUncheckedReturn_AbortOnOOMAllocator pins the abort-on-OOM contract: an
// allocator that NULL-checks its result and calls a never-returning handler
// (via a function pointer, the redis zmalloc shape) never returns NULL, so its
// call sites must NOT be flagged as unchecked-return.
func TestUncheckedReturn_AbortOnOOMAllocator(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdio.h>

static void oom_default(size_t size) {
    fprintf(stderr, "oom %zu\n", size);
    abort();
}
static void (*oom_handler)(size_t) = oom_default;

static void *try_alloc(size_t size) {
    return malloc(size);
}

void *zmalloc(size_t size) {
    void *p = try_alloc(size);
    if (!p) oom_handler(size);
    return p;
}

int use(void) {
    void *p = zmalloc(16);
    return p != 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	defer p.CloseAll()

	dir := t.TempDir()
	path := filepath.Join(dir, "oom.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	if _, err := NewUncheckedReturnDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	byFunc := map[string]int{}
	events, err := store.ListEventsByType(ctx, "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list UNCHECKED_RETURN: %v", err)
	}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		byFunc[fn.Name]++
	}

	// `use` calls the abort-on-OOM zmalloc: no NULL to check, so no event.
	if byFunc["use"] != 0 {
		t.Errorf("use: abort-on-OOM zmalloc has no NULL to check, got %d unchecked-return event(s)", byFunc["use"])
	}
	// `try_alloc` returns malloc's result unchecked, so it IS a passthrough
	// source; but its own call to malloc IS inside try_alloc. The only legit
	// unchecked-return here is try_alloc's malloc call, not zmalloc's.
	_ = byFunc
}
