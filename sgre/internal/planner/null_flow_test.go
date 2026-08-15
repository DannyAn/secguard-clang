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

// nullFlowFixture exercises the flow-sensitive nullness analysis end to end:
// every TP function dereferences a possibly-null pointer without a guard and
// must be reported; every FP function has a definite non-null reassignment (or
// unreachable code) between the null source and the dereference and must be
// suppressed by the CFG/DFG-based nullable_source stage.
const nullFlowFixture = `#include <stdlib.h>

typedef struct Node { int value; struct Node *next; } Node;

static Node g_fallback;

int tp_unchecked_malloc(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    return p->value;
}

int fp_reassign_addressof(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    p = &g_fallback;
    return p->value;
}

int fp_guard_default_literal(void) {
    const char *p = getenv("HOME");
    if (p == NULL) {
        p = "";
    }
    return p[0];
}

int fp_copy_nonnull(void) {
    Node *a = (Node *)malloc(sizeof(Node));
    Node *b = &g_fallback;
    a = b;
    return a->value;
}

int fp_dead_after_return(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    return 0;
    p->value = 1;
    return 2;
}
`

func TestNullFlow_FlowSensitiveSuppression(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "nullflow.c")
	if err := os.WriteFile(path, []byte(nullFlowFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	// True positives must survive the flow-sensitive analysis.
	for _, fn := range []string{"tp_unchecked_malloc"} {
		if !kept[fn] {
			t.Errorf("expected true positive %q to be kept, got candidates: %v", fn, candidateNames(result))
		}
	}

	// False positives (reassignment kill, guard-default, copy, dead code) must be
	// suppressed by the flow-sensitive nullable_source stage.
	for _, fn := range []string{"fp_reassign_addressof", "fp_guard_default_literal", "fp_copy_nonnull", "fp_dead_after_return"} {
		if kept[fn] {
			t.Errorf("expected false positive %q to be suppressed, got candidates: %v", fn, candidateNames(result))
		}
	}

	// The convergence trail must attribute the drops to the flow-sensitive stage.
	sawFlowDrop := false
	for _, d := range result.Summary.Dropped {
		if d.Filter == "nullable_source" && (d.FunctionName == "fp_reassign_addressof" || d.FunctionName == "fp_guard_default_literal") {
			sawFlowDrop = true
		}
	}
	if !sawFlowDrop {
		t.Error("expected a flow-sensitive drop recorded under nullable_source for a reassignment-kill FP")
	}
}

func candidateNames(r *PlanResult) []string {
	names := make([]string, 0, len(r.Candidates))
	for _, c := range r.Candidates {
		names = append(names, c.Target.Function)
	}
	return names
}
