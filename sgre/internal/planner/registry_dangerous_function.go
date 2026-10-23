package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "dangerous-function",
		CWE:              "CWE-676",
		SeedEventType:    "DANGEROUS_FUNCTION",
		EvidenceType:     "DANGEROUS_FUNCTION",
		DefaultSuspicion: "confirmed",
		FilterChain:      "default",
		// A call to a banned function is a POLICY finding — the function itself
		// is the defect, no context matters — so every category is confirmed
		// soundly (a name match, not a may-analysis). EXCEPTION: `assert_usage`
		// is handed to the AI, because whether an assert() guards caller input
		// (a defect) or an internal invariant (fine) needs intent.
		CategoryConfidence: map[string]string{
			"assert_usage":             "suspected",
			"obsolete_api_conditional": "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "dangerous_function", Role: "sink", Detail: fmt.Sprintf("call to banned %s() (%s) at line %d in function %s", c.VariableName, c.Category, c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}
