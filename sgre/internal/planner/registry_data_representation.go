package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "data-representation",
		CWE:               "CWE-843",
		SeedEventType:     "DATA_REPRESENTATION_MISMATCH",
		EvidenceType:      "DATA_REPRESENTATION_MISMATCH",
		DefaultSuspicion:  "suspected",
		FilterChain:       "default",
		FilterFactories:    chainDefault(),
		BuildVerdictFacts: buildDataRepVerdictFacts,
		// A pointer-depth mismatch between a qsort/bsearch base element and the
		// comparator's void* cast is strong evidence of type confusion, but the
		// base's declared type can be a decayed/aliased array, so the AI agent
		// confirms the actual element representation.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "data_representation_mismatch", Role: "sink", Detail: fmt.Sprintf("comparator %s interprets a void* element as %s but the sort base %s holds %s elements at line %d in function %s", c.APIName, c.ActualType, c.VariableName, c.ExpectedType, c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}
