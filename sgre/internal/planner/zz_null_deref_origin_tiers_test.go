//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// TestNullDeref_OriginTiers pins the nullable-origin tier (Evidence Contract
// v2, B1): the tier a candidate lands in decides what the classifier must do,
// so a wrong tier is a protocol break, not a cosmetic issue. The caller-arg
// tier needs a mixed-source fixture and is covered at the buildHintParts /
// verdict-facts unit level (TestBuildHint + TestNullDerefVerdictFacts).
func TestNullDeref_OriginTiers(t *testing.T) {
	t.Run("cfg-proof", func(t *testing.T) {
		src := `void f(void) {
    int *p = NULL;
    p->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "f")
		if c.NullOriginTier != "cfg-proof" {
			t.Fatalf("explicit NULL reaching the deref: tier = %q, want cfg-proof", c.NullOriginTier)
		}
		if !strings.Contains(c.Hint, "null@cfg-proof") {
			t.Fatalf("hint %q must carry null@cfg-proof", c.Hint)
		}
	})

	t.Run("malloc-fail", func(t *testing.T) {
		src := `void f(void) {
    int *p = malloc(4);
    p->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "f")
		if c.NullOriginTier != "malloc-fail" {
			t.Fatalf("unchecked malloc result: tier = %q, want malloc-fail", c.NullOriginTier)
		}
		if !strings.Contains(c.Hint, "null@malloc-fail") {
			t.Fatalf("hint %q must carry null@malloc-fail", c.Hint)
		}
		if c.SuspicionLevel != "confirmed" {
			t.Fatalf("allocator source keeps the confirmed tier, got %q", c.SuspicionLevel)
		}
	})

	t.Run("external-unknown", func(t *testing.T) {
		src := `void f(void) {
    int *p = mylib_obtain();
    p->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "f")
		if c.NullOriginTier != "external-unknown" {
			t.Fatalf("unknown external call: tier = %q, want external-unknown", c.NullOriginTier)
		}
		if !strings.Contains(c.Hint, "null@external-unknown") {
			t.Fatalf("hint %q must carry null@external-unknown", c.Hint)
		}
		if c.SuspicionLevel != "suspected" {
			t.Fatalf("fail-open external stays suspected, got %q", c.SuspicionLevel)
		}
	})

	t.Run("verdict facts per tier", func(t *testing.T) {
		for _, tc := range []struct {
			tier  string
			token string
		}{
			{"cfg-proof", "null@cfg-proof"},
			{"malloc-fail", "null@malloc-fail"},
			{"caller-arg", "null@caller-arg"},
			{"external-unknown", "null@external-unknown"},
		} {
			facts := buildNullDerefVerdictFacts(Candidate{NullOriginTier: tc.tier, VariableName: "p", Line: 9})
			if len(facts) == 0 || facts[0].Token != tc.token {
				t.Fatalf("tier %s: first fact token = %v, want %s", tc.tier, facts, tc.token)
			}
		}
		facts := buildNullDerefVerdictFacts(Candidate{})
		if len(facts) != 1 || facts[0].Token != "guard@none" {
			t.Fatalf("tier-less candidate still carries the machine-verified guard fact, got %v", facts)
		}
	})
}

func firstNullCandidate(t *testing.T, res *PlanResult, fn string) EvidenceItem {
	t.Helper()
	for _, c := range res.Candidates {
		if c.Target.Function == fn {
			return c
		}
	}
	t.Fatalf("no null-deref candidate in function %s", fn)
	return EvidenceItem{}
}
