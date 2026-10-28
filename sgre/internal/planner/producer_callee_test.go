//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestIntegerOverflow_UnsignedSubProducerCalleeEmbedded pins the evidence
// closure: an accumulator fed by an in-scan callee must surface that callee in
// the Hint and embed its body, so the classifier never greps the repo for it.
func TestIntegerOverflow_UnsignedSubProducerCalleeEmbedded(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "tc129_int_overflow_producer.c")); err != nil {
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

	embedded := false
	for _, c := range result.Candidates {
		if c.Target.Function != "unsigned_sub_producer" {
			continue
		}
		if c.CalleeDefFile != "" && c.CalleeDefLine > 0 {
			embedded = true
			if !strings.Contains(c.Hint, "callee@") {
				t.Errorf("candidate at %s:%d has CalleeDef but no callee@ hint: %q", c.Target.File, c.Target.Line, c.Hint)
			}
			if !strings.Contains(c.CalleeDefSignature, "ase_sa_str_connect") {
				t.Errorf("embedded signature = %q, want ase_sa_str_connect", c.CalleeDefSignature)
			}
		}
	}
	if !embedded {
		t.Fatalf("no unsigned_sub_producer candidate carried the producer callee definition: %v", candidateNames(result))
	}
}
