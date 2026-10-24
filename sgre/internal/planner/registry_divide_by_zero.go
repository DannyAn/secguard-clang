package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "divide-by-zero",
		CWE:               "CWE-369",
		SeedEventType:     "DIVIDE_BY_ZERO",
		EvidenceType:      "DIVIDE_BY_ZERO",
		DefaultSuspicion:  "suspected",
		FilterChain:       "divide-by-zero",
		FilterFactories:    chainDivideByZero(),
		BuildVerdictFacts: buildDivideByZeroVerdictFacts,
		// Dedup the SAME divisor divided at many sites into one finding, but keep a
		// confirmed and a suspected division of that divisor distinct: the
		// higher-rank "confirmed" must not mask a suspected site (DBZ-18). The key
		// therefore carries the suspicion tier, not just the divisor.
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("dbz:%d:%s:%s:%s", c.FileID, c.FunctionName, c.VariableName, c.SuspicionLevel)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "divide_by_zero", Role: "sink", Detail: fmt.Sprintf("possible division by zero in function %s at line %d", c.FunctionName, c.Line)},
			}
			// The range engine's own conclusion for the surviving candidate:
			// when it computed a tighter-than-top interval that still contains
			// 0, saying so is the difference between the classifier judging
			// reachability and re-deriving the interval from the ±8 window.
			if c.DivisorInterval != "" {
				frags = append(frags, EvidenceFragment{Type: "divisor_interval", Role: "condition", Detail: fmt.Sprintf("divisor %s interval is %s (includes 0)", c.VariableName, c.DivisorInterval)})
			}
			// A parameter divisor the call-site verdict could not settle: the
			// classifier needs the middle-ground caller facts (who passes a
			// constant, who passes a variable) to judge the unchecked sites.
			if c.DivisorCallers != "" {
				frags = append(frags, EvidenceFragment{Type: "param_flow", Role: "condition", Detail: fmt.Sprintf("divisor %s is a parameter: %s", c.VariableName, c.DivisorCallers)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}
