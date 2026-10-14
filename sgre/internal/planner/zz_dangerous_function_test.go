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

// TestDangerousFunction_AssertSuspected pins the one non-confirmed category:
// whether an assert() guards caller input (a defect) or an internal invariant
// (fine) needs intent, so `assert_usage` is handed to the AI as suspected.
func TestDangerousFunction_AssertSuspected(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	src := `#include <assert.h>
int f(int flags) {
    assert(flags > 0);
    return flags;
}
`
	path := filepath.Join(dir, "as.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
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
	found := false
	for _, c := range res.Candidates {
		if c.Target.Variable == "assert" {
			found = true
			if c.SuspicionLevel != "suspected" {
				t.Errorf("assert candidate = %q, want suspected (handed to AI)", c.SuspicionLevel)
			}
		}
	}
	if !found {
		t.Fatalf("expected an assert candidate, got %d candidates", len(res.Candidates))
	}
}
