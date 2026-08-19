//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestIntegerOverflow_ValueAnalysis locks in the value-analysis-lite expansion:
// beyond `var * var` and `var * sizeof(T)`, the detector now recognizes
// calloc(n, m) and the variable-bounded add/sub/mul-const patterns gated on the
// operand being a function parameter (caller-influenced). A bounded local
// operand must NOT be flagged — that is the precision guard against flooding
// the pipeline with safe `n + 1` null-terminator allocations.
func TestIntegerOverflow_ValueAnalysis(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc66_value_analysis_size.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewIntegerOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "INTEGER_OVERFLOW")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	cats := map[string]map[string]bool{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if cats[fn.Name] == nil {
			cats[fn.Name] = map[string]bool{}
		}
		cats[fn.Name][props.Category] = true
	}

	expect := map[string]string{
		"overflow_add_const": "size_add_overflow",
		"overflow_mul_const": "size_mul_const_overflow",
		"overflow_calloc":    "size_calc_overflow",
		"overflow_sub_const": "size_sub_overflow",
	}
	for fn, cat := range expect {
		if !cats[fn][cat] {
			t.Errorf("expected %s to be flagged as %s, got %v", fn, cat, cats[fn])
		}
	}
	if len(cats["safe_local_add"]) != 0 {
		t.Errorf("expected safe_local_add (bounded local n) NOT to be flagged, got %v", cats["safe_local_add"])
	}
}
