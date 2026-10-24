package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "resource-leak",
		CWE:               "CWE-404",
		SeedEventType:     "RESOURCE_ACQUIRE",
		EvidenceType:      "RESOURCE_LEAK",
		DefaultSuspicion:  "suspected",
		FilterChain:       "resource-leak",
		FilterFactories:    chainResourceLeak(),
		BuildVerdictFacts: buildLeakVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			acquireAPI := ""
			if c.APIName != "" {
				acquireAPI = fmt.Sprintf(" via %s", c.APIName)
			}
			frags := []EvidenceFragment{
				{Type: "resource_acquire", Role: "source", Detail: fmt.Sprintf("resource %s acquired%s in function %s at line %d", c.VariableName, acquireAPI, c.FunctionName, c.Line)},
			}
			if c.DefiniteLeak {
				frags = append(frags, EvidenceFragment{Type: "definite", Role: "condition", Detail: "no release is reachable on any path from the acquire to function exit"})
			} else {
				frags = append(frags, EvidenceFragment{Type: "conditional", Role: "condition", Detail: "released on some paths but potentially leaked on others — trace each error/early-return path for a missing close/release"})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}
