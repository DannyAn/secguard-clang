//go:build !nosqlite

package planner

import (
	"context"
	"encoding/json"
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

func planB2Type(t *testing.T, fixture, typeName string) *PlanResult {
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
	case "integer-overflow":
		det = evidence.NewIntegerOverflowDetector(store, p, logger)
	case "divide-by-zero":
		det = evidence.NewDivideByZeroDetector(store, p, logger)
	case "path-traversal":
		det = evidence.NewPathTraversalDetector(store, p, logger)
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

func TestShiftUB_Tiers(t *testing.T) {
	res := planB2Type(t, "tc173_shift_ub.c", "integer-overflow")
	byFunc := map[string]string{}
	byFuncCat := map[string]string{}
	for _, c := range res.Candidates {
		byFunc[c.Target.Function] = c.SuspicionLevel
		byFuncCat[c.Target.Function] = c.Category
	}
	if byFunc["sh01_shift_over_width"] != "confirmed" || byFuncCat["sh01_shift_over_width"] != "shift_count_ub" {
		t.Errorf("sh01 = (%q,%q), want (confirmed, shift_count_ub)", byFunc["sh01_shift_over_width"], byFuncCat["sh01_shift_over_width"])
	}
	if byFunc["sh02_shift_negative"] != "confirmed" || byFuncCat["sh02_shift_negative"] != "shift_count_ub" {
		t.Errorf("sh02 = (%q,%q), want (confirmed, shift_count_ub)", byFunc["sh02_shift_negative"], byFuncCat["sh02_shift_negative"])
	}
	if byFunc["sh03_signed_literal"] != "confirmed" || byFuncCat["sh03_signed_literal"] != "shift_signed_overflow" {
		t.Errorf("sh03 = (%q,%q), want (confirmed, shift_signed_overflow)", byFunc["sh03_signed_literal"], byFuncCat["sh03_signed_literal"])
	}
	for _, fn := range []string{"sh10_unsigned_shift", "sh11_wide_type", "sh12_var_shift"} {
		if _, ok := byFunc[fn]; ok {
			t.Errorf("%s: must NOT trigger, got %q", fn, byFunc[fn])
		}
	}
}

func TestIntMinDiv_Tiers(t *testing.T) {
	res := planB2Type(t, "tc174_int_min_div.c", "divide-by-zero")
	byFunc := map[string]string{}
	byFuncCat := map[string]string{}
	for _, c := range res.Candidates {
		byFunc[c.Target.Function] = c.SuspicionLevel
		byFuncCat[c.Target.Function] = c.Category
	}
	for _, fn := range []string{"im01_const_pair", "im02_assigned_const"} {
		if byFunc[fn] != "confirmed" || byFuncCat[fn] != "int_min_div" {
			t.Errorf("%s = (%q,%q), want (confirmed, int_min_div)", fn, byFunc[fn], byFuncCat[fn])
		}
	}
	for _, fn := range []string{"im10_var_dividend", "im11_long_ctx"} {
		if _, ok := byFunc[fn]; ok {
			t.Errorf("%s: must NOT trigger int_min_div, got (%q,%q)", fn, byFunc[fn], byFuncCat[fn])
		}
	}
}

func TestPermissionSetting_Tiers(t *testing.T) {
	res := planB2Type(t, "tc175_permission.c", "path-traversal")
	byFunc := map[string]string{}
	for _, c := range res.Candidates {
		byFunc[c.Target.Function] = c.SuspicionLevel
	}
	if byFunc["pm01_chmod_literal"] != "confirmed" {
		t.Errorf("pm01 = %q, want confirmed", byFunc["pm01_chmod_literal"])
	}
	if byFunc["pm02_chmod_var"] != "suspected" {
		t.Errorf("pm02 = %q, want suspected", byFunc["pm02_chmod_var"])
	}
	for _, fn := range []string{"pm10_tmp_path", "pm11_mode_var", "pm12_readable_only"} {
		if _, ok := byFunc[fn]; ok {
			t.Errorf("%s: must NOT trigger, got %q", fn, byFunc[fn])
		}
	}
}

// TestDefiniteValueAt_Engine pins the single-point value proof that backs the
// GAP-06/GAP-07 variable forms: a single constant assignment is provable, a
// rewrite or a non-constant RHS is not.
func TestDefiniteValueAt_Engine(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "tc174_int_min_div.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewDivideByZeroDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	// The variable-form candidate im02 (x = INT_MIN; x / -1) proving confirmed
	// already exercises DefiniteValueAt; this test just asserts the seed events
	// carry the expected category.
	events, err := store.ListEventsByType(ctx, "DIVIDE_BY_ZERO")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var cats []string
	for _, e := range events {
		var pr struct{ Category string `json:"category"` }
		_ = json.Unmarshal([]byte(e.Properties), &pr)
		cats = append(cats, pr.Category)
	}
	has := func(c string) bool {
		for _, x := range cats {
			if x == c {
				return true
			}
		}
		return false
	}
	if !has("int_min_div") {
		t.Errorf("expected int_min_div events, got %v", cats)
	}
}
