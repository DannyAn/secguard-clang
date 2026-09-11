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

// TestDangerousFunction_Confirmed pins the planner tier: a call to a banned
// function is a POLICY finding (sound name match), so it must be confirmed,
// not suspected.
func TestDangerousFunction_Confirmed(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "tc109_dangerous_function.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewDangerousFunctionDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	res, err := NewPlanner(store, p, logger).Plan(ctx, "dangerous-function")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(res.Candidates) == 0 {
		t.Fatalf("expected dangerous-function candidates, got none")
	}
	for _, c := range res.Candidates {
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("candidate %s (banned %s) = %q, want confirmed", c.Target.Function, c.Target.Variable, c.SuspicionLevel)
		}
	}
}
