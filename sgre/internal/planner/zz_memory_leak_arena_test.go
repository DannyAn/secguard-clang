//go:build !nosqlite

package planner

import (
	"context"
	"io"
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

// TestMemoryLeak_BumpAllocatorIsNotPerObjectLeak pins the issue #206 A.3 fix: a
// bump/arena allocator (`pool_alloc` → `g_pool + g_off`, no malloc) hands back
// interior pointers into a pool released wholesale by its owner, so an
// individual result is never a per-object leak. A real malloc leak still is.
func TestMemoryLeak_BumpAllocatorIsNotPerObjectLeak(t *testing.T) {
	src := `#include <stdlib.h>
#include <stddef.h>

#define POOL_SIZE (128u * 1024u * 1024u)

static unsigned char *g_pool;
static size_t         g_off;

void *pool_alloc(size_t n)
{
    void *p = g_pool + g_off;
    g_off += (n + 7u) & ~7u;
    return p;
}

int pool_init(void)
{
    g_pool = (unsigned char *)malloc(POOL_SIZE);
    g_off  = 0;
    return (g_pool != NULL) ? 0 : -1;
}

void pool_deinit(void)
{
    free(g_pool);
    g_pool = NULL;
}

typedef struct { int enabled; int *src; } Cfg;
typedef struct { int value; } Out;

static Out *build(Cfg *c)
{
    if (!c->enabled) {
        return NULL;
    }
    Out *o = (Out *)pool_alloc(sizeof(Out));
    if (o == NULL) {
        return NULL;
    }
    o->value = 1;
    if (c->src == NULL) {
        return NULL;
    }
    return o;
}

int save(Cfg *c)
{
    if (pool_init() != 0) {
        return -1;
    }
    (void)build(c);
    pool_deinit();
    return 0;
}

int real_leak(void)
{
    int *p = (int *)malloc(16);
    return *p;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "arena.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewMemoryLeakDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "memory-leak")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	sawBuild, sawReal := false, false
	for _, c := range res.Candidates {
		switch c.Target.Function {
		case "build":
			sawBuild = true
			t.Errorf("build's pool_alloc result must not be a per-object leak (arena-released wholesale), got var=%s level=%s line=%d",
				c.Target.Variable, c.SuspicionLevel, c.Target.Line)
		case "real_leak":
			sawReal = true
		}
	}
	if !sawReal {
		t.Errorf("real_leak must stay flagged (control)")
	}
	if sawBuild {
		t.Errorf("build must not be flagged")
	}
}
