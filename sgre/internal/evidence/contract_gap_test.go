//go:build !nosqlite

package evidence

import (
	"context"
	"io"
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

	for _, fn := range []string{"partial_guard", "direct_counted", "fully_guarded", "ptr_only_partial", "ptr_only_compound", "never_checked"} {
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

	if suspicion["import_dn_group_tree_refresh"] != "suspected" {
		t.Errorf("PRODUCTION CASE import_dn_group_tree_refresh: expected suspected (E-a sibling evidence), got %q", suspicion["import_dn_group_tree_refresh"])
	}
	if _, present := suspicion["sibling_import_handler"]; present {
		t.Errorf("sibling_import_handler (guarded evidence provider) should NOT be a finding, got %q", suspicion["sibling_import_handler"])
	}
	if suspicion["import_partial_branch"] != "suspected" {
		t.Errorf("import_partial_branch (check in one branch) should stay suspected, got %q", suspicion["import_partial_branch"])
	}
	if suspicion["import_empty_unhandled"] != "suspected" {
		t.Errorf("import_empty_unhandled (count==0 handled but group_data NULL not) should stay suspected, got %q", suspicion["import_empty_unhandled"])
	}
	if _, present := suspicion["import_no_deref"]; present {
		t.Errorf("import_no_deref (field read but not dereferenced) should NOT be a candidate, got %q", suspicion["import_no_deref"])
	}
	if _, present := suspicion["import_callee"]; present {
		t.Errorf("import_callee (caller validates before call) should be dropped, got %q", suspicion["import_callee"])
	}
}

// TestContractGap_Planner pins the deterministic guard-dominance cut: a field
// whose null guard dominates every path to the deref is dropped, while the
// partial-guard residual stays suspected (never machine-confirmed).
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

	count := map[string]int{}
	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		count[c.Target.Function]++
		suspicion[c.Target.Function] = c.SuspicionLevel
	}

	for _, fn := range []string{"partial_guard", "direct_counted", "ptr_only_partial", "ptr_only_compound", "never_checked"} {
		if suspicion[fn] != "suspected" {
			t.Errorf("%s: expected suspected, got %q", fn, suspicion[fn])
		}
	}
	// The guarded first deref of partial_guard / ptr_only_partial is dropped by
	// guard dominance, so only the unguarded site survives as one candidate.
	for _, fn := range []string{"partial_guard", "ptr_only_partial"} {
		if count[fn] != 1 {
			t.Errorf("%s: expected exactly 1 unguarded candidate (guarded site dropped), got %d", fn, count[fn])
		}
	}
	if _, present := suspicion["fully_guarded"]; present {
		t.Errorf("fully_guarded (guard dominates) should be dropped, got %q", suspicion["fully_guarded"])
	}
	// E-c: every caller validates → suppressed; a non-validating caller → kept.
	if _, present := suspicion["callee_validated"]; present {
		t.Errorf("callee_validated (every caller validates group_data) should be dropped, got %q", suspicion["callee_validated"])
	}
	if suspicion["callee_unvalidated"] != "suspected" {
		t.Errorf("callee_unvalidated (caller does not validate) should stay suspected, got %q", suspicion["callee_unvalidated"])
	}
	for _, fn := range []string{"opaque_no_evidence", "written_in_scope", "not_deref"} {
		if _, present := suspicion[fn]; present {
			t.Errorf("%s should not be a candidate", fn)
		}
	}
}
