//go:build !nosqlite

package planner

import (
	"context"
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

// planFixture runs the full detector + planner pipeline on one testdata
// fixture and returns the memory-leak plan result.
func planFixture(t *testing.T, fixture string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(nil, log.LevelWarn)
	p := parser.NewParser()
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, filepath.Join("..", "..", "testdata", fixture)); err != nil {
		t.Fatalf("index %s: %v", fixture, err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)
	res, err := NewPlanner(store, p, logger).Plan(ctx, "memory-leak")
	if err != nil {
		t.Fatalf("plan memory-leak: %v", err)
	}
	return res
}

// TestMemoryLeak_GlobalContainerFieldCandidate pins issue #255 at the plan
// level: the shallow-free candidate is reported at the DELETION path with the
// container reference chain, stays suspected (never auto-confirmed — the
// closed-world release analysis cannot see an out-of-scan destructor), and the
// create-site allocation is re-homed by the container-transfer release instead
// of surfacing as a definite leak in the create function.
func TestMemoryLeak_GlobalContainerFieldCandidate(t *testing.T) {
	res := planFixture(t, "tc183_global_container_field_leak.c")

	var deleteCandidate *EvidenceItem
	var createCandidate *EvidenceItem
	for i := range res.Candidates {
		c := &res.Candidates[i]
		if c.Target.Function == "policy_delete" {
			deleteCandidate = c
		}
		if c.Target.Function == "policy_create" && c.Target.Variable == "cfg" {
			createCandidate = c
		}
	}
	if createCandidate != nil {
		t.Errorf("policy_create still reports cfg as a leak: the allocation was ownership-transferred into the wrapper object and must be dropped by the release event")
	}
	if deleteCandidate == nil {
		t.Fatalf("no memory-leak candidate for the global-container shallow free; candidates=%v", candidateNames(res))
	}
	if deleteCandidate.Target.Variable != "cfg" {
		t.Errorf("delete-path candidate variable = %q, want cfg", deleteCandidate.Target.Variable)
	}
	if deleteCandidate.LeakChain != "g_policy_table[idx] -> policy -> policy->cfg" {
		t.Errorf("leak chain = %q", deleteCandidate.LeakChain)
	}
	if deleteCandidate.LeakShallowFree == "" || deleteCandidate.LeakFieldAlloc == "" {
		t.Errorf("shallow-free/field-alloc witnesses missing: shallow=%q alloc=%q", deleteCandidate.LeakShallowFree, deleteCandidate.LeakFieldAlloc)
	}
	if deleteCandidate.SuspicionLevel != "suspected" {
		t.Errorf("container-field leak must stay suspected, got %q", deleteCandidate.SuspicionLevel)
	}
	hint := strings.Join(deleteCandidate.HintTokens, " ")
	for _, want := range []string{"container-field@", "shallow-free@", "field-alloc@"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint %q misses token %q", hint, want)
		}
	}
}
