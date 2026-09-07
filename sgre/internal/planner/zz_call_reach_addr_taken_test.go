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

// TestCallReach_AddrTakenStaticIsReachable pins the indirect-call fix: a static
// function whose address is referenced (a function-pointer table entry) is
// invoked indirectly, so the direct CALL graph has no edge into it but it must
// NOT be dropped as "unreachable". A never-referenced static helper still is.
func TestCallReach_AddrTakenStaticIsReachable(t *testing.T) {
	src := `#include <stdlib.h>

typedef int pthread_rwlock_t;
static int pthread_rwlock_init(pthread_rwlock_t *l, const void *a) { return 0; }
static int pthread_rwlock_destroy(pthread_rwlock_t *l) { return 0; }
static void *https_malloc(unsigned long n) { return 0; }

static pthread_rwlock_t g_client_registry_lock;
static void **g_https_client_record;

static void https_dfx_client_registry_init(void) {
    pthread_rwlock_init(&g_client_registry_lock, 0);
    g_https_client_record = (void **)https_malloc(8);
    if (g_https_client_record == 0) {
        return;
    }
}

typedef void (*init_fn)(void);
static init_fn g_init_fns[] = { https_dfx_client_registry_init };

void module_init(void) {
    for (int i = 0; i < 1; i++) {
        g_init_fns[i]();
    }
}

static void dead_helper(void) {
    pthread_rwlock_init(&g_client_registry_lock, 0);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "addr_taken.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewResourceLeakDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "resource-leak")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if !kept["https_dfx_client_registry_init"] {
		t.Errorf("https_dfx_client_registry_init (addr-taken static via pointer table) should be kept, got %v", candidateNames(result))
	}
	if kept["dead_helper"] {
		t.Errorf("dead_helper (never-referenced static) should be dropped as unreachable, got %v", candidateNames(result))
	}
}
