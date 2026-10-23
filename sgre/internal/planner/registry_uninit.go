package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "uninit",
		CWE:               "CWE-457",
		SeedEventType:     "VALUE_USE",
		EvidenceType:      "UNINIT_USE",
		DefaultSuspicion:  "suspected",
		FilterChain:       "uninit",
		BuildVerdictFacts: buildUninitVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "uninit_use", Role: "sink", Detail: fmt.Sprintf("uninitialized variable '%s' used in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
			}
			if c.DeclLine > 0 {
				if c.Origin == "heap_uninit" {
					frags = append(frags, EvidenceFragment{Type: "allocation", Role: "source", Detail: fmt.Sprintf("variable '%s' allocated at line %d", c.VariableName, c.DeclLine)})
				} else {
					frags = append(frags, EvidenceFragment{Type: "declaration", Role: "source", Detail: fmt.Sprintf("variable '%s' declared at line %d", c.VariableName, c.DeclLine)})
				}
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"Use of an uninitialized variable is a real defect",
			"The pipeline tracks initialization state through the CFG",
		},
		RequiredEvidence: []string{"declaration without initialization", "use location", "path from declaration to use"},
		KnownLimitations: []string{
			"Heap/struct initialization via calloc/memset may not be fully recognized",
			"Cross-function initialization via output parameters may be missed",
		},
	})
}
