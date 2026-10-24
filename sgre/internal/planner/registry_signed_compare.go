package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "signed-compare",
		CWE:              "CWE-681",
		SeedEventType:    "SIGNED_COMPARE",
		EvidenceType:     "SIGNED_COMPARE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		FilterFactories:    chainDefault(),
		Categories:       []string{"signed_compare"},
		// The detector only emits when the compared variable's declared type is
		// provably unsigned (an `unsigned`/`size_t`/`uint*_t` spelling), and an
		// unsigned value is never `< 0` — the dead comparison is a confirmed
		// CWE-681 defect. The suspected default is a backstop, never reached in
		// practice.
		CategoryConfidence: map[string]string{
			"signed_compare": "confirmed",
		},
		BuildVerdictFacts: buildSignedCompareVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "signed_compare", Role: "sink", Detail: fmt.Sprintf("unsigned value compared with zero/negative at line %d in function %s", c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}

func buildSignedCompareVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 3)
	if c.Category != "" {
		facts = append(facts, VerdictFact{
			Token:  "cat@" + c.Category,
			Detail: "detector category: " + c.Category + " (signed_compare)",
		})
	}
	if c.ExpectedType != "" && c.ActualType != "" {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("sign@%s-vs-%s", c.ExpectedType, c.ActualType),
			Detail: fmt.Sprintf("signed/unsigned comparison: %s vs %s (type-width model proves the sign mismatch)", c.ExpectedType, c.ActualType),
		})
	}
	return facts
}
