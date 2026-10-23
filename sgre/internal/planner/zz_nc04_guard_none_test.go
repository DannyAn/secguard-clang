//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// NC-04: the guard@none verdict fact is redundant for cfg-proof (the CFG
// proof already entails "no guard") and its old wording overstated the fact
// for the fail-open tiers — "no same-function null guard" read as "no guard
// exists anywhere", when the pipeline only proved it found no DOMINATING
// same-function guard. cfg-proof now omits it; the other tiers get
// tier-aware wording that keeps the AI checking caller-side and
// cross-function guards.
func TestNullDerefVerdictFactsGuardNoneTiered(t *testing.T) {
	facts := buildNullDerefVerdictFacts(Candidate{NullOriginTier: "cfg-proof", VariableName: "p", Line: 10})
	for _, f := range facts {
		if f.Token == "guard@none" {
			t.Errorf("cfg-proof must not emit guard@none (redundant with the machine proof), got %+v", facts)
		}
	}

	found := false
	facts = buildNullDerefVerdictFacts(Candidate{NullOriginTier: "caller-arg", VariableName: "p", Line: 10})
	for _, f := range facts {
		if f.Token != "guard@none" {
			continue
		}
		found = true
		if !strings.Contains(f.Detail, "may still exist") {
			t.Errorf("caller-arg guard@none must note caller-side/cross-function guards may still exist, got %q", f.Detail)
		}
	}
	if !found {
		t.Errorf("caller-arg must emit guard@none (fail-open tier needs the guard-state fact)")
	}
}
