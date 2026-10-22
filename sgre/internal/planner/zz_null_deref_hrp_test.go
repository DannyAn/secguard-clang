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

// planHrpSrc runs the full null-deref pipeline over one or more fixture
// files written to a temp dir (the hrp example is a two-file component).
func planHrpSrc(t *testing.T, sources map[string]string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	for name, src := range sources {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		idx := indexer.NewIndexer(store, logger)
		if _, err := idx.Index(ctx, path); err != nil {
			t.Fatalf("index %s: %v", name, err)
		}
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)

	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}
	return res
}

func hrpFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

// TestNullDeref_HRPActivateSession_ReassignFromProvenNullable locks the
// user-provided PATTERN-02: `ctx` is reassigned from a tree-internal
// proven-nullable wrapper (`malloc` + `if (ctx == NULL) return NULL`) inside
// the `ctx == NULL` guard branch and then dereferenced with no re-check. The
// entry null guard does NOT protect the dereference (the branch BODY is
// where the null value lived; the reassignment brings in a fresh
// maybe-NULL), so the candidate is machine-proved (confirmed tier — the
// same proven retNullable channel as ND-16).
func TestNullDeref_HRPActivateSession_ReassignFromProvenNullable(t *testing.T) {
	res := planHrpSrc(t, map[string]string{
		"hrp_session.c": hrpFixture(t, "tc164_hrp_session_null_deref.c"),
	})
	found := false
	for _, c := range res.Candidates {
		if c.Target.Function != "Hrp_ActivateSession" {
			continue
		}
		if c.Target.Variable != "ctx" {
			continue
		}
		found = true
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("reassignment from a tree-internal malloc wrapper (literal return NULL path) is proven-nullable; the unchecked dereference must be confirmed, got %q", c.SuspicionLevel)
		}
	}
	if !found {
		t.Fatal("PATTERN-02: ctx->active after the unchecked Hrp_AllocSession reassignment must surface a candidate")
	}
}

// TestNullDeref_HRPMemberChain_Unguarded locks the user-provided
// PATTERN-03: `ctx->negotiator->state` — the member pointer was seeded from
// an extern assumed-nullable lookup (Hrp_GetNegotiator) inside
// Hrp_AllocSession and dereferenced with no guard. The opaque-origin
// candidate stays suspected for the AI (the extern contract is unproven).
func TestNullDeref_HRPMemberChain_Unguarded(t *testing.T) {
	res := planHrpSrc(t, map[string]string{
		"hrp_session.c": hrpFixture(t, "tc164_hrp_session_null_deref.c"),
	})
	found := false
	for _, c := range res.Candidates {
		if c.Target.Function != "Hrp_ActivateSession" {
			continue
		}
		if c.Target.Variable != "ctx->negotiator" {
			continue
		}
		found = true
		if c.SuspicionLevel != "suspected" {
			t.Errorf("the member chain from an extern assumed-nullable lookup must stay suspected for the AI, got %q", c.SuspicionLevel)
		}
	}
	if !found {
		t.Fatal("PATTERN-03: ctx->negotiator->state must surface a candidate")
	}
}

// TestNullDeref_HRPIpcCastUntrusted locks the user-provided PATTERN-09
// (CWD-1034): `msg->ctxPtr` — external IPC data — is cast to a session
// pointer and dereferenced with no validation. The cast-to-pointer local
// must surface an opaque-origin candidate whose source points at the cast
// line (the evidence chain the classifier needs to judge the
// untrusted-pointer risk).
func TestNullDeref_HRPIpcCastUntrusted(t *testing.T) {
	res := planHrpSrc(t, map[string]string{
		"hrp_session.c": hrpFixture(t, "tc164_hrp_session_null_deref.c"),
	})
	found := false
	for _, c := range res.Candidates {
		if c.Target.Function != "Hrp_HandleIpcMsg" {
			continue
		}
		if c.Target.Variable != "ctx" {
			continue
		}
		found = true
	}
	if !found {
		t.Fatal("PATTERN-09: the ctx cast from msg->ctxPtr must surface a candidate for the unguarded dereference")
	}
}

// TestNullDeref_HRPPeerBranchDeref locks the user-provided PATTERN-05: the
// parameter is dereferenced inside a branch whose condition tests `state`
// (not the pointer) and on the fall-through path with no null guard. The
// branch offers no protection for peer, so the caller-arg candidate must
// surface (suspected — the external caller contract decides).
func TestNullDeref_HRPPeerBranchDeref(t *testing.T) {
	res := planHrpSrc(t, map[string]string{
		"hrp_peer.c": hrpFixture(t, "tc165_hrp_peer_branch_deref.c"),
	})
	found := false
	for _, c := range res.Candidates {
		if c.Target.Function != "Hrp_UpdatePeerState" {
			continue
		}
		if c.Target.Variable != "peer" {
			continue
		}
		found = true
	}
	if !found {
		t.Fatal("PATTERN-05: the fall-through peer->lastChange dereference with no null guard must surface a candidate")
	}
}

// TestNullDeref_HRPFixedForms_NoCandidates locks the user remediations:
// checked reassignment + checked member (fix 1), external-data validation +
// table lookup (fix 2), and the entry null guard (fix 3). None of the three
// may surface a candidate — the guards must kill every seeded source.
func TestNullDeref_HRPFixedForms_NoCandidates(t *testing.T) {
	res := planHrpSrc(t, map[string]string{
		"hrp_fixed.c": hrpFixture(t, "tc166_hrp_fixed_forms.c"),
	})
	for _, c := range res.Candidates {
		t.Errorf("fixed form %s (var %s at line %d) must not surface a candidate", c.Target.Function, c.Target.Variable, c.Target.Line)
	}
	if res.CandidateCount() != 0 {
		t.Fatalf("expected 0 candidates across all three fixed forms, got %d", res.CandidateCount())
	}
}
