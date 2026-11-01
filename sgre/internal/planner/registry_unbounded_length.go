package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "unbounded-length-copy",
		CWE:              "CWE-1284",
		SeedEventType:    "UNBOUNDED_LENGTH",
		EvidenceType:     "UNBOUNDED_LENGTH",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		FilterFactories:  chainDefault(),
		// The trust boundary (is the length attacker-controlled?) is a semantic
		// judgment the machine cannot prove, so every shape stays suspected.
		BuildVerdictFacts: buildUnboundedLengthVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{{
				Type:   "unbounded_length",
				Role:   "sink",
				Detail: fmt.Sprintf("an externally-sourced length %s flows into a %s size argument in %s at line %d with no upper-bound guard", c.VariableName, c.APIName, c.FunctionName, c.Line),
			}}
			if c.Origin != "" {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: fmt.Sprintf("the length originates at %s", c.Origin)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildUnboundedLengthVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 3)
	if c.Origin != "" {
		facts = append(facts, VerdictFact{
			Token:  "len-taint@" + c.Origin,
			Detail: fmt.Sprintf("the length originates at %s — a network/file read return value (the external trust boundary)", c.Origin),
		})
	}
	if c.APIName != "" {
		facts = append(facts, VerdictFact{
			Token:  "len-sink@" + c.APIName + ":" + fmt.Sprint(c.Line),
			Detail: fmt.Sprintf("the length reaches %s at line %d as a size argument", c.APIName, c.Line),
		})
	}
	facts = append(facts, VerdictFact{
		Token:  "guard@none-upper",
		Detail: "no upper-bound check dominates the sink (CFG proof) — the length is not clamped or range-checked before use; a `n < 0` check is NOT an upper bound",
	})
	return facts
}
