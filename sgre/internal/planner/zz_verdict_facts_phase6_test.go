package planner

import (
	"strings"
	"testing"
)

// TestIntegerOverflowVerdictFacts pins the integer-overflow VerdictFacts
// contract: category / operand origins / sink shape are surfaced as
// structured tokens so the AI does not need to open the source to classify.
func TestIntegerOverflowVerdictFacts(t *testing.T) {
	c := Candidate{
		Category:         "size_calc_overflow",
		LHSKind:          "param",
		SubLHSInfluenced: true,
		RHSKind:          "const",
		SubRHSInfluenced: false,
		SubSink:          "call_arg",
	}
	facts := buildIntegerOverflowVerdictFacts(c)
	if len(facts) < 4 {
		t.Fatalf("expected >= 4 facts, got %d", len(facts))
	}
	var tokens []string
	for _, f := range facts {
		tokens = append(tokens, f.Token)
	}
	joined := strings.Join(tokens, "|")
	for _, want := range []string{"cat@size_calc_overflow", "lhs@param", "rhs@const", "sink@call_arg"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing token %q in %v", want, tokens)
		}
	}
	// Confirmed (detector-proved literal) candidates must carry cat@definite_overflow.
	literal := Candidate{Category: "definite_overflow"}
	facts = buildIntegerOverflowVerdictFacts(literal)
	found := false
	for _, f := range facts {
		if f.Token == "cat@definite_overflow" {
			found = true
		}
	}
	if !found {
		t.Errorf("literal-overflow candidate missing cat@definite_overflow: %v", facts)
	}
}

// TestUncheckedReturnVerdictFacts pins the unchecked-return VerdictFacts
// contract: api@ / contract@known|unknown / discard / callee@<file>:<line>
// tokens let the AI classify from the index row + embedded Callee Definition
// without opening the source.
func TestUncheckedReturnVerdictFacts(t *testing.T) {
	c := Candidate{
		APIName:       "my_alloc",
		ContractKnown: false,
		CalleeDefFile: "src/factory.c",
		CalleeDefLine: 42,
	}
	facts := buildUncheckedReturnVerdictFacts(c)
	var tokens []string
	for _, f := range facts {
		tokens = append(tokens, f.Token)
	}
	joined := strings.Join(tokens, "|")
	for _, want := range []string{"api@my_alloc", "contract@unknown", "callee@src/factory.c:42"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing token %q in %v", want, tokens)
		}
	}

	// Known contract must say contract@known.
	known := Candidate{APIName: "malloc", ContractKnown: true}
	tokens = nil
	for _, f := range buildUncheckedReturnVerdictFacts(known) {
		tokens = append(tokens, f.Token)
	}
	if !strings.Contains(strings.Join(tokens, "|"), "contract@known") {
		t.Errorf("contract-known candidate missing contract@known: %v", tokens)
	}

	// Discard marker.
	discard := Candidate{APIName: "close", ContractKnown: true, Consumed: "discard"}
	tokens = nil
	for _, f := range buildUncheckedReturnVerdictFacts(discard) {
		tokens = append(tokens, f.Token)
	}
	if !strings.Contains(strings.Join(tokens, "|"), "discard") {
		t.Errorf("discard candidate missing discard token: %v", tokens)
	}
}

// TestVerdictFactsCoverageAll25Types pins the P0-3 contract: every registered
// vuln type has a non-nil BuildVerdictFacts, so no candidate reaches the AI
// without structured verdict facts (the hint-token-only era is over).
func TestVerdictFactsCoverageAll25Types(t *testing.T) {
	for _, name := range AllVulnTypes() {
		spec, err := GetVulnTypeSpec(name)
		if err != nil {
			t.Fatalf("GetVulnTypeSpec(%q): %v", name, err)
		}
		if spec.BuildVerdictFacts == nil {
			t.Errorf("type %s: BuildVerdictFacts is nil", name)
		}
	}
}
