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

// TestNullDeref_AbortOnOOMWrapper pins the scan-tree resolution of the
// abort-on-OOM contract: a wrapper `p = alloc(); if (!p) oom_handler(); return
// p;` — where oom_handler aborts via a FUNCTION POINTER — never returns NULL,
// so `q = wrapper(); q[0]` is NOT a null-deref (the redis zmalloc shape).
func TestNullDeref_AbortOnOOMWrapper(t *testing.T) {
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

void *xmalloc(size_t size) {
    void *p = try_alloc(size);
    if (!p) oom_handler(size);
    return p;
}

void use(void) {
    void *q = xmalloc(16);
    q[0] = 1;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	defer p.CloseAll()

	dir := t.TempDir()
	path := filepath.Join(dir, "nd.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)

	res, err := NewPlanner(store, p, logger).Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}
	for _, c := range res.Candidates {
		if c.Target.Function == "use" && c.Target.Variable == "q" {
			t.Errorf("q = xmalloc() must not be a null-deref (xmalloc aborts on OOM): suspicion=%q hint=%q", c.SuspicionLevel, c.Hint)
		}
	}
}
