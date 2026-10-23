package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "argument-type",
		CWE:               "CWE-686",
		SeedEventType:     "ARGUMENT_TYPE_MISMATCH",
		EvidenceType:      "ARGUMENT_TYPE_MISMATCH",
		DefaultSuspicion:  "suspected",
		FilterChain:       "default",
		BuildVerdictFacts: buildArgumentTypeVerdictFacts,
		// An incompatible pointer cast is evidence of a type reinterpretation,
		// but an explicit cast is not proof of a defect (it can be an intentional
		// ABI/opaque boundary), so the AI agent judges intent rather than the
		// pipeline auto-confirming a cast.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "argument_type_mismatch", Role: "sink", Detail: fmt.Sprintf("call to %s passes %s as %s at line %d in function %s", c.APIName, c.ActualType, c.ExpectedType, c.Line, c.FunctionName)},
			}
			if c.CastType != "" {
				frags = append(frags, EvidenceFragment{Type: "explicit_cast", Role: "source", Detail: fmt.Sprintf("explicit cast %s reinterprets object %s (%s)", c.CastType, c.VariableName, c.ActualType)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}
