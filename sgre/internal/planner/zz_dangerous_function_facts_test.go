package planner

import (
	"strings"
	"testing"
)

// TestDangerousFunctionVerdictFacts pins the P0-2 contract: a dangerous-
// function candidate carries the policy@<category> token so the AI can
// distinguish a POLICY violation (banned_function / obsolete_api — the
// function itself is the defect) from a context-sensitive defect
// (assert_usage — needs intent judgment).
func TestDangerousFunctionVerdictFacts(t *testing.T) {
	c := Candidate{
		Category:     "unsafe_string",
		VariableName: "strcpy",
	}
	facts := buildDangerousFunctionVerdictFacts(c)
	var tokens []string
	for _, f := range facts {
		tokens = append(tokens, f.Token)
	}
	joined := strings.Join(tokens, "|")
	if !strings.Contains(joined, "policy@unsafe_string") {
		t.Errorf("missing policy@unsafe_string in %v", tokens)
	}
	if !strings.Contains(joined, "api@strcpy") {
		t.Errorf("missing api@strcpy in %v", tokens)
	}
	// The policy token's detail must distinguish POLICY violations from
	// context-sensitive defects.
	for _, f := range facts {
		if f.Token == "policy@unsafe_string" {
			if !strings.Contains(f.Detail, "POLICY") {
				t.Errorf("policy@unsafe_string detail missing POLICY marker: %q", f.Detail)
			}
		}
	}
}
