//go:build !nosqlite

package planner

import (
	"context"
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

// runHrpBufPlan indexes a fixture through the full memory-detector pipeline
// and plans double-free.
func runHrpBufPlan(t *testing.T, fixture string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	idx := indexer.NewIndexer(store, logger)
	fixturePath := filepath.Join("..", "..", "testdata", fixture)
	if _, err := idx.Index(ctx, fixturePath); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewAliasBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)
	res, err := NewPlanner(store, p, logger).Plan(ctx, "double-free")
	if err != nil {
		t.Fatalf("plan double-free: %v", err)
	}
	return res
}

// TestDoubleFree_GotoCleanupSameFunction locks the user-provided PATTERN-01:
// the error path frees buf, then `goto cleanup` jumps to the cleanup label —
// placed AFTER `return 0;` — where buf is freed again. Both frees execute on
// the rc != 0 path, so the freed-state reaches the second free on EVERY path
// that gets there: the candidate is machine-proved (confirmed). This pins
// the CFG fix: the label block after a terminator must be modeled and the
// goto must link to it, or the flow filter dismisses the candidate as
// unreachable.
func TestDoubleFree_GotoCleanupSameFunction(t *testing.T) {
	res := runHrpBufPlan(t, "tc167_hrp_buf_double_free.c")
	found := false
	for _, c := range res.Candidates {
		if c.Target.Function != "hrp_pkt_encode" {
			continue
		}
		if c.Target.Variable != "buf" {
			continue
		}
		found = true
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("goto-cleanup double free: both frees run on the rc != 0 path (must), want confirmed, got %q", c.SuspicionLevel)
		}
		hasFree := false
		for _, tok := range c.HintTokens {
			if tok == "free@30,38" {
				hasFree = true
			}
		}
		if !hasFree {
			t.Errorf("candidate hint must carry free@30,38, got %v", c.HintTokens)
		}
	}
	if !found {
		t.Fatal("PATTERN-01: the goto-cleanup double free must survive the flow filter (label block after return was previously dropped from the CFG)")
	}
}

// TestDoubleFree_CrossFunctionMayFree locks the user-provided PATTERN-06:
// queue_push frees its argument on its own failure branch (a may-free
// release helper), and the caller frees msg again after the rc check. The
// candidate must surface with may_free semantics — suspected, never
// auto-confirmed, the hint carries may-free + cond@queue_push.
func TestDoubleFree_CrossFunctionMayFree(t *testing.T) {
	res := runHrpBufPlan(t, "tc167_hrp_buf_double_free.c")
	found := false
	for _, c := range res.Candidates {
		if c.Target.Function != "hrp_msg_build" {
			continue
		}
		if c.Target.Variable != "msg" {
			continue
		}
		found = true
		if c.SuspicionLevel != "suspected" {
			t.Errorf("cross-function may-free double free must stay suspected for the AI, got %q", c.SuspicionLevel)
		}
		if !c.MayFree {
			t.Error("the first release is conditional (queue_push frees only when its own condition holds); the candidate must carry may_free")
		}
		hasMay, hasCond := false, false
		for _, tok := range c.HintTokens {
			if tok == "may-free" {
				hasMay = true
			}
			if tok == "cond@queue_push" {
				hasCond = true
			}
		}
		if !hasMay || !hasCond {
			t.Errorf("candidate hint must carry may-free and cond@queue_push, got %v", c.HintTokens)
		}
	}
	if !found {
		t.Fatal("PATTERN-06: the caller's second free after queue_push's conditional internal free must surface a candidate")
	}
}

// TestDoubleFree_HrpBufFixedForms_NoCandidates locks the user remediations:
// the single cleanup free with immediate nulling (fix 1) and the corrected
// queue_push ownership contract (fix 2) produce zero double-free candidates.
func TestDoubleFree_HrpBufFixedForms_NoCandidates(t *testing.T) {
	res := runHrpBufPlan(t, "tc168_hrp_buf_fixed.c")
	for _, c := range res.Candidates {
		t.Errorf("fixed form %s (var %s at line %d) must not surface a double-free candidate", c.Target.Function, c.Target.Variable, c.Target.Line)
	}
	if res.CandidateCount() != 0 {
		t.Fatalf("expected 0 double-free candidates across both fixed forms, got %d", res.CandidateCount())
	}
}

// TestDoubleFree_GotoNullGuardFallThroughUntouched locks that the goto
// dead-end semantics for NULL facts still hold after linking goto→label
// edges: `if (p == NULL) goto out;` must leave the fall-through path with p
// non-null (the deref after the guard is dead), while the out label sees
// the NULL fact. Guards against the CFG fix regressing null-guard analysis.
func TestDoubleFree_GotoNullGuardFallThroughUntouched(t *testing.T) {
	src := `#include <stdlib.h>
int guard_goto(int *p) {
    if (p == NULL) {
        goto out;
    }
    *p = 1;
    return 0;
out:
    return -1;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "guard_goto.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)
	res, err := NewPlanner(store, p, logger).Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}
	for _, c := range res.Candidates {
		if c.Target.Function == "guard_goto" && c.Target.Variable == "p" {
			t.Errorf("the fall-through deref after `if (p == NULL) goto out;` is guarded; no null-deref candidate expected, got %s at line %d", c.SuspicionLevel, c.Target.Line)
		}
	}
}
