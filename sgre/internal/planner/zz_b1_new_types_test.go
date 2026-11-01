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

func planNewType(t *testing.T, fixture, typeName string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", fixture)); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	var det evidence.Detector
	switch typeName {
	case "stack-address-escape":
		det = evidence.NewStackEscapeDetector(store, p, logger)
	case "invalid-free":
		det = evidence.NewInvalidFreeDetector(store, p, logger)
	case "switch-fallthrough":
		det = evidence.NewSwitchFlowDetector(store, p, logger)
	default:
		t.Fatalf("unknown type %q", typeName)
	}
	if _, err := det.Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	res, err := NewPlanner(store, p, logger).Plan(ctx, typeName)
	if err != nil {
		t.Fatalf("plan %s: %v", typeName, err)
	}
	return res
}

func TestStackEscape_Tiers(t *testing.T) {
	res := planNewType(t, "tc170_stack_escape.c", "stack-address-escape")
	byFunc := map[string]string{}
	for _, c := range res.Candidates {
		byFunc[c.Target.Function] = c.SuspicionLevel
	}
	for _, fn := range []string{"m1a_return_addr", "m1b_return_array", "m1c_return_elem_addr", "m1d_return_field_addr"} {
		if byFunc[fn] != "confirmed" {
			t.Errorf("%s = %q, want confirmed", fn, byFunc[fn])
		}
	}
	if byFunc["m2_store"] != "suspected" {
		t.Errorf("m2_store = %q, want suspected", byFunc["m2_store"])
	}
	if byFunc["m3_async_arg"] != "suspected" {
		t.Errorf("m3_async_arg = %q, want suspected", byFunc["m3_async_arg"])
	}
}

func TestInvalidFree_Tiers(t *testing.T) {
	res := planNewType(t, "tc171_invalid_free.c", "invalid-free")
	if len(res.Candidates) == 0 {
		t.Fatalf("expected invalid-free candidates, got none")
	}
	for _, c := range res.Candidates {
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("candidate %s (%s) = %q, want confirmed", c.Target.Function, c.Target.Variable, c.SuspicionLevel)
		}
	}
}

func TestSwitchFallthrough_Tiers(t *testing.T) {
	res := planNewType(t, "tc172_switch_flow.c", "switch-fallthrough")
	if len(res.Candidates) == 0 {
		t.Fatalf("expected switch-fallthrough candidates, got none")
	}
	for _, c := range res.Candidates {
		if c.SuspicionLevel != "suspected" {
			t.Errorf("candidate %s = %q, want suspected", c.Target.Function, c.SuspicionLevel)
		}
	}
}
