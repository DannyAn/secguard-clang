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

// planNullDerefFull runs the complete null-deref pipeline including the
// inter-procedural CallerNullDetector (the shared planNullDeref helper omits it,
// so cross-function param-null cases would silently read as "not detected").
func planNullDerefFull(t *testing.T, src string) []string {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "nullability.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
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
	evidence.NewCallerNullDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	names := make([]string, 0, len(result.Candidates))
	for _, c := range result.Candidates {
		names = append(names, c.Target.Function)
	}
	return names
}

func setOf(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// TestContractNullability_IntraProcedural pins the intra-procedural half: a bare
// parameter deref with no provable NULL source is not a finding, an explicit
// NULL assignment is, and a dominating guard filters both shapes.
func TestContractNullability_IntraProcedural(t *testing.T) {
	src := `
typedef struct { int field; } Context;

void process(Context *ctx) { ctx->field = 1; }

void guarded_return(Context *ctx) {
    if (ctx == NULL) return;
    ctx->field = 1;
}

void guarded_scope(Context *ctx) {
    if (ctx != NULL) ctx->field = 1;
}

void local_null(void) {
    Context *ctx = NULL;
    ctx->field = 1;
}
`
	has := setOf(planNullDerefFull(t, src))

	if !has["local_null"] {
		t.Errorf("local_null (ctx=NULL then deref) must stay a null-deref, got %v", has)
	}
	if has["guarded_return"] {
		t.Errorf("guarded_return must NOT be a null-deref, got %v", has)
	}
	if has["guarded_scope"] {
		t.Errorf("guarded_scope must NOT be a null-deref, got %v", has)
	}
	// The open-chain model grades a zero-caller function's parameter open
	// only when its type is NOT defined in the scan tree (the incomplete-type
	// issue); Context IS defined here, so process stays closed (v0.9.4
	// contract — see the opaque_null tests for the open half).
	if has["process"] {
		t.Errorf("process (bare param deref, tree-defined type) must NOT be a null-deref, got %v", has)
	}
}

// TestContractNullability_InterProcedural pins the caller-null contract: a
// parameter dereferenced without a guard is a null-deref only when a caller can
// pass NULL (literal) or a value it has not proven non-null (unguarded); a
// caller whose early-return check dominates the call proves non-null and must
// NOT surface.
func TestContractNullability_InterProcedural(t *testing.T) {
	base := `typedef struct { int value; } Context;
static void process(Context *ctx) {
    ctx->value = 1;
}
`
	t.Run("literal NULL caller", func(t *testing.T) {
		src := base + "void c(void) {\n    process(NULL);\n}\n"
		if has := setOf(planNullDerefFull(t, src)); !has["process"] {
			t.Errorf("process(NULL) must surface as a null-deref, got %v", has)
		}
	})
	t.Run("guarded caller", func(t *testing.T) {
		src := base + "void c(Context *ctx) {\n    if (ctx == NULL) return;\n    process(ctx);\n}\n"
		if has := setOf(planNullDerefFull(t, src)); has["process"] {
			t.Errorf("guarded caller must NOT surface, got %v", has)
		}
	})
	t.Run("unguarded caller", func(t *testing.T) {
		// c's parameter type (Context) is tree-defined, so the zero-caller
		// entry stays closed and process must not surface. The incomplete-type
		// form (opaque typedef at the entry) is the one that surfaces — pinned
		// in TestOpaqueNullEndToEndInTreeCaller.
		src := base + "void c(Context *ctx) {\n    process(ctx);\n}\n"
		if has := setOf(planNullDerefFull(t, src)); has["process"] {
			t.Errorf("unguarded caller of a tree-defined type must not surface, got %v", has)
		}
	})
}

// TestContractNullability_AnyCallerViolates pins the path-dependent contract: a
// guarded caller does not rescue a function that another caller violates. The
// violation is a literal-NULL call site (the definite witness); guarded chains
// alone keep a function closed.
func TestContractNullability_AnyCallerViolates(t *testing.T) {
	src := `
typedef struct { int value; } Context;

static void process(Context *ctx) {
    ctx->value = 1;
}

void guarded(Context *ctx) {
    if (ctx == NULL) return;
    process(ctx);
}

void violator(void) {
    process(NULL);
}
`
	has := setOf(planNullDerefFull(t, src))
	if !has["process"] {
		t.Errorf("process must surface when one caller passes literal NULL, got %v", has)
	}
}
