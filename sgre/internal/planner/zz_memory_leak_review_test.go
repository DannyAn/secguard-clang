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

// planMemoryLeak runs the full memory-leak pipeline and returns the converged
// candidates keyed by function name.
func planMemoryLeak(t *testing.T, src string) map[string]EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "ml.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	evidence.NewMemoryLeakDetector(store, p, logger).Detect(ctx)
	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "memory-leak")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	out := map[string]EvidenceItem{}
	for _, c := range res.Candidates {
		out[c.Target.Function] = c
	}
	return out
}

// ML-05: free(q) where q = p releases p's block — no leak.
// ML-06: free((void*)p) releases p — no leak.
func TestMemoryLeakReview_AliasAndCastRelease(t *testing.T) {
	src := `#include <stdlib.h>
int alias_free(int c) {
    int *p = malloc(8);
    int *q = p;
    free(q);
    return 0;
}
int cast_free(int c) {
    int *p = malloc(8);
    free((void *)p);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["alias_free"]; ok {
		t.Errorf("alias_free: free(q) with q=p must not leak p, got %v", keysOf(got))
	}
	if _, ok := got["cast_free"]; ok {
		t.Errorf("cast_free: free((void*)p) must not leak p, got %v", keysOf(got))
	}
}

// ML-07: g = (T*)p escapes p; ML-09: extern-declared global store escapes p.
func TestMemoryLeakReview_EscapeVariants(t *testing.T) {
	src := `#include <stdlib.h>
extern int *g1;
int cast_escape(int c) {
    int *p = malloc(8);
    g1 = (int *)p;
    return 0;
}
int extern_global(int c) {
    extern int *global_buf;
    int *p = malloc(8);
    global_buf = p;
    return 0;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["cast_escape"]; ok {
		t.Errorf("cast_escape: g1 = (int*)p escapes p, got %v", keysOf(got))
	}
	if _, ok := got["extern_global"]; ok {
		t.Errorf("extern_global: store to extern global escapes p, got %v", keysOf(got))
	}
}

// ML-11: implicit allocators (strdup / asprintf / getline / realpath(NULL)) are
// allocations and leak when never freed.
func TestMemoryLeakReview_ImplicitAllocators(t *testing.T) {
	src := `#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int strdup_leak(void) {
    char *p = strdup("x");
    return 0;
}
int asprintf_leak(int c) {
    char *p = 0;
    asprintf(&p, "%d", c);
    return 0;
}
int getline_leak(int c) {
    char *p = 0;
    size_t n = 0;
    getline(&p, &n, stdin);
    return 0;
}
int realpath_leak(void) {
    char *p = realpath("/tmp", 0);
    return 0;
}
int strdup_free(void) {
    char *p = strdup("x");
    free(p);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	for _, fn := range []string{"strdup_leak", "asprintf_leak", "getline_leak", "realpath_leak"} {
		if _, ok := got[fn]; !ok {
			t.Errorf("%s: implicit allocation must be reported, got %v", fn, keysOf(got))
		}
	}
	if _, ok := got["strdup_free"]; ok {
		t.Errorf("strdup_free: freed, must not leak, got %v", keysOf(got))
	}
}

// ML-12: self-realloc leaks the OLD block on failure; realloc-into-temp does not
// leak the source.
func TestMemoryLeakReview_Realloc(t *testing.T) {
	src := `#include <stdlib.h>
int self_realloc(int c) {
    int *p = malloc(8);
    p = realloc(p, 16);
    free(p);
    return 0;
}
int safe_realloc(int c) {
    int *p = malloc(8);
    int *tmp = realloc(p, 16);
    free(tmp);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["self_realloc"]; !ok {
		t.Errorf("self_realloc: p=realloc(p,n) leaks the old block on failure, got %v", keysOf(got))
	}
	if _, ok := got["safe_realloc"]; ok {
		t.Errorf("safe_realloc: realloc into a temp consumes p, must not leak, got %v", keysOf(got))
	}
}

// ML-01/18: a pointer with no free/transfer/escape is a DEFINITE leak and must
// be confirmed; a conditional free stays suspected.
func TestMemoryLeakReview_Confirmed(t *testing.T) {
	src := `#include <stdlib.h>
int definite(void) {
    int *p = malloc(8);
    return 0;
}
int conditional(int c) {
    int *p = malloc(8);
    if (c) free(p);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	c, ok := got["definite"]
	if !ok {
		t.Fatalf("definite must be a candidate, got %v", keysOf(got))
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("definite (never freed/escaped/returned) should be confirmed, got %q", c.SuspicionLevel)
	}
	if cc, ok := got["conditional"]; ok && cc.SuspicionLevel == "confirmed" {
		t.Errorf("conditional (freed on one path only) must stay suspected, got %q", cc.SuspicionLevel)
	}
}

// ML-13: a create function with a paired destroy must NOT be blanket-exempted —
// a temporary allocation it never returns/frees is a genuine leak and must be
// reported, while the returned pointer is a transfer.
func TestMemoryLeakReview_RAIICoarseExemption(t *testing.T) {
	src := `#include <stdlib.h>
void *foo_new(void) {
    void *p = malloc(16);
    void *tmp = malloc(8);
    return p;
}
void foo_free(void *p) { free(p); }
`
	got := planMemoryLeak(t, src)
	if _, ok := got["foo_new"]; !ok {
		t.Errorf("foo_new: the temporary tmp leaks and must be reported, got %v", keysOf(got))
	}
}

// ML-15: a cast-wrapped return (`return (T *)p`) is an ownership transfer, not a
// leak.
func TestMemoryLeakReview_CastWrappedReturn(t *testing.T) {
	src := `#include <stdlib.h>
int *cast_return(void) {
    int *p = malloc(8);
    return (int *)p;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["cast_return"]; ok {
		t.Errorf("cast_return: return (int*)p transfers ownership, must not leak, got %v", keysOf(got))
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
