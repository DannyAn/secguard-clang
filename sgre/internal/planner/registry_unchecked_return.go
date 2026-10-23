package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "unchecked-return",
		CWE:               "CWE-252",
		SeedEventType:     "UNCHECKED_RETURN",
		EvidenceType:      "UNCHECKED_RETURN",
		DefaultSuspicion:  "suspected",
		FilterChain:       "unchecked-return",
		BuildVerdictFacts: buildUncheckedReturnVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "unchecked_return", Role: "sink", Detail: fmt.Sprintf("return value of %s is not checked in function %s at line %d", c.APIName, c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			// contract@unknown puts the proof burden on the classifier, so the
			// candidate file must CONTAIN the callee body: cross-file static
			// factories are the norm and neither the ±8 window nor the Failure
			// Contract line can hold a callee from another file. The report
			// renders ## Callee Definition from CalleeDefFile:Line-EndLine, so
			// the classifier proves/refutes the sentinel in place instead of
			// spending a source READ on a body the index already located.
			// An external callee gets an explicit "no body in scan" so the
			// classifier goes to API knowledge instead of burning READs on a
			// search that cannot succeed.
			if c.APIName != "" && !c.ContractKnown {
				if c.CalleeDefFile != "" {
					detail := fmt.Sprintf("callee %s is defined in the scan at %s:%d", c.APIName, c.CalleeDefFile, c.CalleeDefLine)
					if c.CalleeDefSignature != "" {
						detail += fmt.Sprintf(" (signature: %s)", c.CalleeDefSignature)
					}
					detail += " — its body is embedded under ## Callee Definition; prove or refute the failure sentinel from it (no source read needed)"
					frags = append(frags, EvidenceFragment{Type: "callee_definition", Role: "callee", Detail: detail})
				} else {
					frags = append(frags, EvidenceFragment{Type: "callee_definition", Role: "callee", Detail: fmt.Sprintf("callee %s has no definition in the scan (external/library function) — there is no body to read; prove the contract from API knowledge or dismiss", c.APIName)})
				}
			}
			return frags
		},
	})
}
