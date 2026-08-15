package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestIntegerOverflow_RelationalGuardOnly locks in the precision fix for the
// "wraparound inside a bounds check" pattern: the arithmetic must be an operand
// of a relational comparison (<, <=, >, >=) in a condition. A pointer-arithmetic
// expression inside an strcmp equality (== 0) whose operand later feeds malloc
// is NOT an overflow guard and must not be flagged.
func TestIntegerOverflow_RelationalGuardOnly(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc46_integer_overflow_scope.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewIntegerOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "INTEGER_OVERFLOW")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	flagged := map[string]bool{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		flagged[fn.Name] = true
	}

	if !flagged["real_wraparound"] {
		t.Errorf("expected real_wraparound (relational bounds check) to be flagged, got %v", flagged)
	}
	if flagged["not_overflow_strcmp"] {
		t.Errorf("expected not_overflow_strcmp (strcmp == 0 equality) NOT to be flagged, got %v", flagged)
	}
	if flagged["not_overflow_malloc_null"] {
		t.Errorf("expected not_overflow_malloc_null (malloc(...) == NULL with -> operand) NOT to be flagged, got %v", flagged)
	}
}
