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
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestIntegerOverflow_SizeofProduct(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc64_int_overflow_sizeof.c")); err != nil {
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

	if !flagged["overflow_sizeof_alloc"] {
		t.Errorf("expected overflow_sizeof_alloc (n * sizeof(int)) to be flagged, got %v", flagged)
	}
	if !flagged["safe_var_var_alloc"] {
		t.Errorf("expected safe_var_var_alloc (m * n) to be flagged, got %v", flagged)
	}
	if flagged["safe_constant_alloc"] {
		t.Errorf("expected safe_constant_alloc (constant 256) NOT to be flagged, got %v", flagged)
	}
}

func TestBoundedCopyOverflow(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc65_bounded_copy_overflow.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	flagged := map[string]bool{}
	counts := map[string]int{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		flagged[fn.Name] = true
		counts[fn.Name]++
	}

	if !flagged["bounded_copy_overflow"] {
		t.Errorf("expected bounded_copy_overflow (strncpy dst[128] with n=256) to be flagged, got %v", flagged)
	}
	if flagged["safe_bounded_copy"] {
		t.Errorf("expected safe_bounded_copy (strncpy dst[256] with n=128) NOT to be flagged, got %v", flagged)
	}
	if flagged["bounded_copy_var_size"] {
		t.Errorf("expected bounded_copy_var_size (variable n, cannot prove) NOT to be flagged, got %v", flagged)
	}
	// The bounded-copy overflow call must be reported exactly once: the
	// size-vs-capacity check is authoritative and must not fall through to the
	// generic buffer-overflow path (which previously double-reported it).
	if n := counts["bounded_copy_overflow"]; n != 1 {
		t.Errorf("expected bounded_copy_overflow to emit exactly 1 event, got %d", n)
	}
}

// TestBoundedCopyVarSize locks in the variable-length bounded-copy tier: a
// strncpy into a fixed array whose copy size is a caller-influenced parameter
// is emitted as bounded_copy_var_size (the AI agent reasons over the length),
// while a bounded local copy size is suppressed.
func TestBoundedCopyVarSize(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc67_bounded_copy_var_size.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
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

	if !cats["var_size_overflow"]["bounded_copy_var_size"] {
		t.Errorf("expected var_size_overflow (strncpy dst[16] with caller-controlled n) to be flagged bounded_copy_var_size, got %v", cats["var_size_overflow"])
	}
	if len(cats["var_size_local"]) != 0 {
		t.Errorf("expected var_size_local (bounded local n) NOT to be flagged, got %v", cats["var_size_local"])
	}
}

// TestBoundedCopyPlannerSeeding locks in the planner-seeding fix: the
// bounded_copy_overflow / bounded_copy_var_size categories must be part of the
// buffer-overflow seed allowlist, or the detector's events are silently dropped
// before the AI agent ever sees them (a false-negative on the v0.2.0 strncpy
// feature that the earlier reverse self-review missed).
func TestBoundedCopyPlannerSeeding(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc65_bounded_copy_overflow.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	pl := planner.NewPlanner(store, nil, logger)
	res, err := pl.Plan(ctx, "buffer-overflow")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	seen := map[string]string{}
	for _, c := range res.Candidates {
		seen[c.Target.Function] = c.SuspicionLevel
	}
	if _, ok := seen["bounded_copy_overflow"]; !ok {
		t.Errorf("expected bounded_copy_overflow to surface as a buffer-overflow candidate, got %v", seen)
	} else if seen["bounded_copy_overflow"] != "confirmed" {
		t.Errorf("expected bounded_copy_overflow to be confirmed (constant size proven), got %q", seen["bounded_copy_overflow"])
	}
}
