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

// recallFixture is a recall (no-false-negative) guard: every function is a
// genuine defect that the convergence pipeline MUST keep. It pins the two
// over-convergence bugs found on zlib (line-keyed kill collision in the uninit
// flow filter; init_declarator recording the RHS read as an assignment) so they
// cannot silently regress into missed findings.
const recallFixture = `#include <stdlib.h>

typedef struct Node { int value; struct Node *next; } Node;
typedef struct Pair { int a; int b; } Pair;

Node *mayfail(void) { return 0; }

/* ===== null-deref true positives ===== */
int nd_basic(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    return p->value;
}
int nd_reassign_null(int c) {
    Node *p = (Node *)malloc(sizeof(Node));
    if (c) p = NULL;
    return p->value;
}
int nd_copy(int c) {
    Node *p = (Node *)malloc(sizeof(Node));
    Node *q = p;
    return q->value;
}
int nd_call_return(void) {
    Node *p = mayfail();
    return p->value;
}

/* ===== uninit true positives ===== */
int ui_whole(void) {
    int a;
    return a;
}
int ui_partial_struct(void) {
    Pair s;
    s.a = 1;
    return s.b;
}
int ui_copy_uninit(void) {
    int a;
    int b = a;
    return b;
}
int ui_loop_skip(int n) {
    int x;
    while (n > 0) { x = n; n--; }
    return x;
}

/* ===== use-after-free true positives ===== */
int uaf_basic(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    free(p);
    return p->value;
}
int uaf_alias(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    Node *q = p;
    free(p);
    return q->value;
}
`

func TestRecall_NoFalseNegatives(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "recall.c")
	if err := os.WriteFile(path, []byte(recallFixture), 0644); err != nil {
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
	evidence.NewInterproceduralDetector(store, p, logger).Detect(ctx)
	evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx)
	evidence.NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	expected := map[string][]string{
		"null-deref":     {"nd_basic", "nd_reassign_null", "nd_copy", "nd_call_return"},
		"uninit":         {"ui_whole", "ui_partial_struct", "ui_copy_uninit", "ui_loop_skip"},
		"use-after-free": {"uaf_basic", "uaf_alias"},
	}

	for _, vt := range []string{"null-deref", "uninit", "use-after-free"} {
		pl := NewPlanner(store, p, logger)
		res, err := pl.Plan(ctx, vt)
		if err != nil {
			t.Fatalf("%s plan: %v", vt, err)
		}
		caught := map[string]bool{}
		for _, c := range res.Candidates {
			caught[c.Target.Function] = true
		}
		for _, fn := range expected[vt] {
			if !caught[fn] {
				t.Errorf("%s: expected true positive %q to be kept (recall), got candidates %v", vt, fn, candidateNames(res))
			}
		}
	}
}
