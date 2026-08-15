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

// uninitFixture: a genuine stack uninit (declared, never written, then used)
// must be kept; a variable declared uninitialized but written before use must be
// suppressed by the flow-sensitive definite_init filter.
const uninitFixture = `#include <stdlib.h>

int tp_stack_uninit(void) {
    int a;
    return a + 1;
}

int fp_assigned_before_use(void) {
    int b;
    b = 7;
    return b + 1;
}

int fp_struct_field_init(void) {
    struct { int x; int y; } s;
    s.x = 1;
    s.y = 2;
    return s.x + s.y;
}
`

func TestDefiniteInitFilter_InfiniteForLoop(t *testing.T) {
	// A var killed in a `for (;;)` body must not reach a use after the loop
	// (the loop has no condition, so it can only exit via break — which still
	// passes through the kill). This guards the CFG bug where a fabricated
	// "condition false" exit for for(;;) bypassed the body's kill.
	src := `struct code { int bits; int val; };
int f(int mode, int *lencode, int bits, int *out) {
    struct code here;
    switch (mode) {
    case 1:
        for (;;) {
            here = *(struct code *)lencode;
            if (here.bits <= bits) break;
            lencode++;
        }
        out[0] = here.val;
        break;
    default:
        break;
    }
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "forloop.c")
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
	for _, c := range result.Candidates {
		if c.Target.Function == "f" && c.Target.Variable == "here" {
			t.Errorf("here should be suppressed: it is assigned in the for(;;) body before use, got candidate at line %d", c.Target.Line)
		}
	}
}

func TestDefiniteInitFilter_FlowSensitive(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "uninit.c")
	if err := os.WriteFile(path, []byte(uninitFixture), 0644); err != nil {
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

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if !kept["tp_stack_uninit"] {
		t.Errorf("expected genuine uninit tp_stack_uninit to be kept, got %v", candidateNames(result))
	}
	if kept["fp_assigned_before_use"] {
		t.Errorf("expected fp_assigned_before_use to be suppressed (b is assigned before use), got %v", candidateNames(result))
	}
	if kept["fp_struct_field_init"] {
		t.Errorf("expected fp_struct_field_init to be suppressed (fields are assigned), got %v", candidateNames(result))
	}
}

func TestDefiniteInitFilter_ChainedAssign(t *testing.T) {
	// `code = first = index = 0` initializes all three targets; only the
	// outermost target used to be recognized as a write, leaving first/index
	// flagged as uninitialized reads (cf. zlib blast.c).
	src := `int fp_chained_assign(void) {
    int first;
    int index;
    int code;
    code = first = index = 0;
    return first + index + code;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "chained.c")
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
	for _, c := range result.Candidates {
		if c.Target.Function == "fp_chained_assign" {
			t.Errorf("expected chained assignment code = first = index = 0 to initialize all three, got candidate %v at line %d", c.Target.Variable, c.Target.Line)
		}
	}
}

func TestDefiniteInitFilter_ForInitLoopCounter(t *testing.T) {
	// A loop counter declared bare (`unsigned i;`) but initialized in a for-init
	// (`for (i = 0; ...)`) is definitely initialized before a later use — it
	// must not be flagged. This is the redis hnsw.c loop-counter pattern that
	// previously flooded uninit.
	src := `float f(const float *x, const float *y, unsigned dim) {
    unsigned i;
    for (i = 0; i + 15 < dim; i += 16) {
        x[i] = 0;
    }
    for (; i < dim; i++) {
        x[i] = 0;
    }
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "forinit.c")
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
	for _, c := range result.Candidates {
		if c.Target.Variable == "i" {
			t.Errorf("expected for-init loop counter i to be definitely initialized, got candidate at line %d", c.Target.Line)
		}
	}
}
