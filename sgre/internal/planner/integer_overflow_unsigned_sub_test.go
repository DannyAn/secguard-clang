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

func TestIntegerOverflow_UnsignedSubCandidateSurvivesPlanner(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "tc100_unsigned_sub_underflow.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewIntegerOverflowDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	result, err := NewPlanner(store, p, logger).Plan(ctx, "integer-overflow")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := make(map[string]bool)
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
		if c.Target.Function == "unsigned_sub_param" && c.Category != "unsigned_sub_underflow" {
			t.Errorf("category = %q, want unsigned_sub_underflow", c.Category)
		}
	}
	if !kept["unsigned_sub_param"] {
		t.Errorf("unsigned_sub_param missing from candidates: %v", candidateNames(result))
	}
	if kept["unsigned_sub_guarded"] {
		t.Errorf("unsigned_sub_guarded should be suppressed: %v", candidateNames(result))
	}
}
