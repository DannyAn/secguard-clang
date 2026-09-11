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

// planHardcodedSecret runs the hardcoded-secret pipeline over one testdata
// fixture and returns the converged candidates keyed by variable name.
func planHardcodedSecret(t *testing.T, fixture string) map[string]EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", fixture)); err != nil {
		t.Fatalf("index %s: %v", fixture, err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewHardcodedSecretDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect %s: %v", fixture, err)
	}

	result, err := NewPlanner(store, p, logger).Plan(ctx, "hardcoded-secret")
	if err != nil {
		t.Fatalf("plan %s: %v", fixture, err)
	}
	byVar := make(map[string]EvidenceItem, len(result.Candidates))
	for _, c := range result.Candidates {
		byVar[c.Target.Variable] = c
	}
	return byVar
}

// TestHardcodedSecret_NameOnlyStaysSuspected pins the fix for a skill whose
// rules were unreachable: a name-only match (`password = "admin123"`) used to be
// seeded `confirmed`, so the scan auto-confirmed it without AI review and the
// skill's placeholder / test-credential false-positive rules could never run.
// It must stay suspected; only a value-proven literal is auto-confirmed.
func TestHardcodedSecret_NameOnlyStaysSuspected(t *testing.T) {
	cands := planHardcodedSecret(t, "tc95_hardcoded_secret_value_only.c")

	for _, v := range []string{"password", "db_password"} {
		c, ok := cands[v]
		if !ok {
			t.Fatalf("no hardcoded-secret candidate for %s", v)
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("%s (name-only match) suspicion = %q, want suspected (AI must judge the value)", v, c.SuspicionLevel)
		}
	}
}

// TestHardcodedSecret_ValueProvenIsConfirmed is the direction guard: a literal
// proven by its value stays auto-confirmed, so the fix does not drag every
// hardcoded-secret candidate into an AI review turn.
func TestHardcodedSecret_ValueProvenIsConfirmed(t *testing.T) {
	cands := planHardcodedSecret(t, "tc95_hardcoded_secret_value_only.c")

	for _, v := range []string{"high_entropy", "conn"} {
		c, ok := cands[v]
		if !ok {
			t.Fatalf("no hardcoded-secret candidate for %s", v)
		}
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("%s (proven by its value) suspicion = %q, want confirmed", v, c.SuspicionLevel)
		}
	}
}
