//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func planLoopBound(t *testing.T, fixture, typeName string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", fixture)); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := graph.NewCallGraphBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := graph.NewDataFlowBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := evidence.NewLoopBoundDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	res, err := NewPlanner(store, p, logger).Plan(ctx, typeName)
	if err != nil {
		t.Fatalf("plan %s: %v", typeName, err)
	}
	return res
}

func TestLoopBound_TiersAndCWE(t *testing.T) {
	res := planLoopBound(t, "tc180_loop_bound.c", "loop-bound")
	byFunc := map[string]string{}
	for _, c := range res.Candidates {
		byFunc[c.Target.Function] = c.SuspicionLevel
		if c.SuspicionLevel != "suspected" {
			t.Errorf("%s = %q, want suspected (never auto-confirmed)", c.Target.Function, c.SuspicionLevel)
		}
	}
	for _, fn := range []string{"lb01_param_bound", "lb02_recv_bound", "lb03_mul_bound"} {
		if byFunc[fn] != "suspected" {
			t.Errorf("%s: expected a suspected candidate, got %q", fn, byFunc[fn])
		}
	}
	if got := CWEForType("loop-bound"); got != "CWE-834" {
		t.Errorf("CWEForType(loop-bound) = %q, want CWE-834", got)
	}
	if got := CWEForCategory("loop-bound", "unchecked_input_bound"); got != "CWE-606" {
		t.Errorf("CWEForCategory(unchecked_input_bound) = %q, want CWE-606", got)
	}
	if got := CWEForCategory("loop-bound", "bound_mul"); got != "CWE-834" {
		t.Errorf("CWEForCategory(bound_mul) = %q, want CWE-834", got)
	}
}
