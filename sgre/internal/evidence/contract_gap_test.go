//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// TestContractGap_Detector pins the E-b evidence gate and the deterministic cuts
// at the detector level: a caller-supplied pointer field is only a CONTRACT_GAP
// when it is dereferenced, count/length-gated, null-checked somewhere (self
// evidence), and NOT written in-scope.
func TestContractGap_Detector(t *testing.T) {
	store, p := setupDetector(t, "tc_contract_gap.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewContractGapDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("contract_gap detect: %v", err)
	}

	flagged := eventFuncs(t, store, "CONTRACT_GAP")

	for _, fn := range []string{"partial_guard", "direct_counted", "fully_guarded", "ptr_only_partial", "ptr_only_compound", "never_checked",
		"block_guarded", "block_guarded_local", "block_guarded_else", "short_circuit_guarded", "guard_then_deref"} {
		if !flagged[fn] {
			t.Errorf("%s: expected CONTRACT_GAP (deref + self/sibling evidence), got none", fn)
		}
	}
	for _, fn := range []string{"opaque_no_evidence", "written_in_scope", "not_deref"} {
		if flagged[fn] {
			t.Errorf("%s: expected NO CONTRACT_GAP (no evidence / written-in-scope / no-deref), got one", fn)
		}
	}
}

// TestContractGap_ProductionCase pins the production shape
// (import_dn_group_tree_refresh): a caller-supplied pointer field cast and
// dereferenced with NO self null-check is caught via the E-a sibling contract,
// and its variants (partial guard, empty-unhandled, no-deref, caller-validated)
// each land in the right bucket.
func TestContractGap_ProductionCase(t *testing.T) {
	store, p := setupDetector(t, "tc_contract_gap_prod.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewContractGapDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("contract_gap detect: %v", err)
	}

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "implicit-contract")
	if err != nil {
		t.Fatalf("plan implicit-contract: %v", err)
	}

	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		suspicion[c.Target.Function] = c.SuspicionLevel
	}

	if suspicion["import_dn_group_tree_refresh"] == "suspected" {
		t.Errorf("PRODUCTION CASE import_dn_group_tree_refresh (sibling-only, no self-guard) should be auto-dismissed per issue #206 A.6, got %q", suspicion["import_dn_group_tree_refresh"])
	}
	if _, present := suspicion["sibling_import_handler"]; present {
		t.Errorf("sibling_import_handler (guarded evidence provider) should NOT be a finding, got %q", suspicion["sibling_import_handler"])
	}
	if suspicion["import_partial_branch"] != "suspected" {
		t.Errorf("import_partial_branch (self-guard + sibling) should stay suspected, got %q", suspicion["import_partial_branch"])
	}
	if suspicion["import_empty_unhandled"] == "suspected" {
		t.Errorf("import_empty_unhandled (sibling-only, no group_data self-guard) should be auto-dismissed per issue #206 A.6, got %q", suspicion["import_empty_unhandled"])
	}
	if _, present := suspicion["import_no_deref"]; present {
		t.Errorf("import_no_deref (field read but not dereferenced) should NOT be a candidate, got %q", suspicion["import_no_deref"])
	}
	if _, present := suspicion["import_callee"]; present {
		t.Errorf("import_callee (caller validates before call) should be dropped, got %q", suspicion["import_callee"])
	}
}

// TestContractGap_Planner pins the deterministic guard-dominance cut and the
// shape-level clustering: a field whose null guard dominates every path to the
// deref is dropped (early-exit OR same-block guard, issue #216), while the
// partial-guard residual stays suspected (never machine-confirmed). Sites that
// share a file, field, access form, evidence tier and guard structure are folded
// into one representative that keeps every sink line and the folded
// (function:line) sites.
func TestContractGap_Planner(t *testing.T) {
	store, p := setupDetector(t, "tc_contract_gap.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewContractGapDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("contract_gap detect: %v", err)
	}

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "implicit-contract")
	if err != nil {
		t.Fatalf("plan implicit-contract: %v", err)
	}

	reps := map[string]planner.EvidenceItem{}
	folded := map[string]string{}
	for _, c := range res.Candidates {
		reps[c.Target.Function] = c
		for _, site := range c.ClusterSites {
			fn, _, _ := strings.Cut(site, ":")
			folded[fn] = site
		}
	}

	// Every same-block guard shape is dropped: the deref sits inside the guarded
	// branch, so entering it is the proof. never_checked is the sibling-only tier
	// (pre-dismissed per issue #206 A.6); fully_guarded is the early-exit form.
	for _, fn := range []string{"fully_guarded", "block_guarded", "block_guarded_local", "block_guarded_else", "short_circuit_guarded", "never_checked", "callee_validated"} {
		if c, present := reps[fn]; present {
			t.Errorf("%s (guarded / pre-dismissed) should be dropped, got %q", fn, c.SuspicionLevel)
		}
		if site, present := folded[fn]; present {
			t.Errorf("%s is guarded — it must not be folded into a shape cluster (%s)", fn, site)
		}
	}

	// The two count-gated resp_t sites are structurally different shapes — the
	// derived-local subscript (`tree[i]`) and the direct field subscript
	// (`resp->group_data[i]`) — so each stays its own contract question. This is
	// the same split the benchmark's Phase-17 ground truth (P17-09 / P17-10)
	// encodes: clustering must not merge different access forms.
	for _, fn := range []string{"partial_guard", "direct_counted"} {
		c, ok := reps[fn]
		if !ok {
			t.Errorf("%s must stay its own candidate (different access form), got %v", fn, candidateNames(res.Candidates))
			continue
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("%s: expected suspected, got %q", fn, c.SuspicionLevel)
		}
		if len(c.ClusterSites) != 0 {
			t.Errorf("%s must not be folded into another shape, got cluster_sites=%v", fn, c.ClusterSites)
		}
	}

	// Same access form + evidence tier + guard structure: one representative.
	// ptr_only_partial (alias-member, line 94) is the earliest of the alias-member
	// no-count sites, so it folds ptr_only_compound (line 104).
	shapeAlias, ok := reps["ptr_only_partial"]
	if !ok {
		t.Fatalf("ptr_only_partial must represent the alias-member no-count shape, got %v", candidateNames(res.Candidates))
	}
	for _, line := range []int{94, 104} {
		if !hasLine(shapeAlias.DerefLines, line) {
			t.Errorf("alias-member shape must carry sink line %d, got %v", line, shapeAlias.DerefLines)
		}
	}
	if !hasSite(folded, "ptr_only_compound:104") {
		t.Errorf("alias-member shape must fold ptr_only_compound:104, got %v", folded)
	}

	// guard_then_deref is the over-drop control: its guard does NOT dominate the
	// afterwards deref at line 155, so it must stay evidence. Being the earliest
	// direct-member site it replaces ptr_only_partial's role for the direct shape
	// and folds callee_unvalidated (line 216).
	shapeDirect, ok := reps["guard_then_deref"]
	if !ok {
		t.Fatalf("guard_then_deref (deref after the guard block) must stay a candidate and represent the direct-member shape, got %v", candidateNames(res.Candidates))
	}
	if shapeDirect.SuspicionLevel != "suspected" {
		t.Errorf("guard_then_deref: expected suspected, got %q", shapeDirect.SuspicionLevel)
	}
	for _, line := range []int{155, 216} {
		if !hasLine(shapeDirect.DerefLines, line) {
			t.Errorf("direct-member shape must carry sink line %d, got %v", line, shapeDirect.DerefLines)
		}
	}
	if !hasSite(folded, "callee_unvalidated:216") {
		t.Errorf("direct-member shape must fold callee_unvalidated:216, got %v", folded)
	}

	// A different parameter struct type is a different contract question: it never
	// shares a cluster with resp_t's group_data.
	if _, ok := reps["payload_partial"]; !ok {
		t.Errorf("payload_partial (payload_t.items) must stay its own candidate, got %v", candidateNames(res.Candidates))
	}

	// Five shapes remain from seven surviving sites: two structurally identical
	// pairs fold, the rest stay separate.
	if len(res.Candidates) != 5 || res.Summary.ShapeFolded != 2 {
		t.Errorf("expected 5 shape representatives folding 2 sites, got %d candidates / shape_folded=%d (%v)",
			len(res.Candidates), res.Summary.ShapeFolded, candidateNames(res.Candidates))
	}

	for _, fn := range []string{"opaque_no_evidence", "written_in_scope", "not_deref"} {
		if _, present := reps[fn]; present {
			t.Errorf("%s should not be a candidate", fn)
		}
	}
}

func hasLine(lines []int, want int) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

func hasSite(sites map[string]string, want string) bool {
	for _, s := range sites {
		if s == want {
			return true
		}
	}
	return false
}

func candidateNames(cands []planner.EvidenceItem) []string {
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.Target.Function)
	}
	return names
}
