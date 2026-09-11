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

// TestSignalHandler_Confirmed pins the planner tier: a direct non-async-signal-
// safe call in a registered handler is sound (the POSIX safe list is fixed), so
// the candidate must be confirmed (auto-ticket safe) — not suspected.
func TestSignalHandler_Confirmed(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "tc108_signal_handler.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewSignalHandlerDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	res, err := NewPlanner(store, p, logger).Plan(ctx, "signal-handler")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(res.Candidates) == 0 {
		t.Fatalf("expected signal-handler candidates, got none")
	}
	for _, c := range res.Candidates {
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("candidate %s (unsafe %s) = %q, want confirmed", c.Target.Function, c.Target.Variable, c.SuspicionLevel)
		}
	}
}
