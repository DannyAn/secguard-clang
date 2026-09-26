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

// uninitHeapStructPlan runs the full pipeline on src and returns the converged
// uninit candidates keyed by "func|variable".
func uninitHeapStructPlan(t *testing.T, src string) map[string]EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "u.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	out := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		out[c.Target.Function+"|"+c.Target.Variable] = c
	}
	return out
}

// UN-06: a conditional field write initializes the field on only some paths, so
// the read must NOT be dropped; but a write on BOTH branches is definite and the
// planner drops it. This locks the detector's conservative emission to the
// planner's CFG must-analysis.
func TestUninitReviewHeap_ConditionalFieldWrite(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct S { int len; } S;
int one_branch(int c) {
    S *p = malloc(sizeof(S));
    if (c) { p->len = 1; }
    return p->len;
}
int both_branches(int c) {
    S *p = malloc(sizeof(S));
    if (c) { p->len = 1; } else { p->len = 2; }
    return p->len;
}
`
	got := uninitHeapStructPlan(t, src)
	if _, ok := got["one_branch|p"]; !ok {
		t.Errorf("one_branch (conditional write then read) must stay a candidate, got %v", keys(got))
	}
	if _, ok := got["both_branches|p"]; ok {
		t.Errorf("both_branches (written on every path) must be dropped, got %v", keys(got))
	}
}

// UN-17/18: a heap block never written after malloc is a definite uninitialized
// read and must be confirmed by the planner.
func TestUninitReviewHeap_Confirmed(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct S { int len; } S;
int f(void) {
    S *p = malloc(sizeof(S));
    return p->len;
}
`
	got := uninitHeapStructPlan(t, src)
	c, ok := got["f|p"]
	if !ok {
		t.Fatalf("f (malloc then p->len) should be a candidate, got %v", keys(got))
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("f should be confirmed (never written on any path), got %q", c.SuspicionLevel)
	}
}

// UN-01/06 (struct): a conditional struct-field write is not definite; both
// branches are.
func TestUninitReviewStruct_ConditionalFieldWrite(t *testing.T) {
	src := `typedef struct S { int len; } S;
int one_branch(int c) {
    S s;
    if (c) { s.len = 1; }
    return s.len;
}
int both_branches(int c) {
    S s;
    if (c) { s.len = 1; } else { s.len = 2; }
    return s.len;
}
`
	got := uninitHeapStructPlan(t, src)
	if _, ok := got["one_branch|s"]; !ok {
		t.Errorf("one_branch (conditional write then read) must stay a candidate, got %v", keys(got))
	}
	if _, ok := got["both_branches|s"]; ok {
		t.Errorf("both_branches (written on every path) must be dropped, got %v", keys(got))
	}
}

// UN-17/18 (struct): a struct field never written is a definite partial-init.
func TestUninitReviewStruct_Confirmed(t *testing.T) {
	src := `typedef struct S { int len; } S;
int f(void) {
    S s;
    return s.len;
}
`
	got := uninitHeapStructPlan(t, src)
	c, ok := got["f|s"]
	if !ok {
		t.Fatalf("f (uninit struct field read) should be a candidate, got %v", keys(got))
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("f should be confirmed (field never written), got %q", c.SuspicionLevel)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
