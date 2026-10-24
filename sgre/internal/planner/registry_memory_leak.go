package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "memory-leak",
		CWE:               "CWE-401",
		SeedEventType:     "MEMORY_ALLOC",
		EvidenceType:      "MEMORY_LEAK",
		DefaultSuspicion:  "suspected",
		FilterChain:       "memory-leak",
		FilterFactories:    chainMemoryLeak(),
		BuildVerdictFacts: buildLeakVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			allocAPI := ""
			if c.APIName != "" {
				allocAPI = fmt.Sprintf(" via %s", c.APIName)
			}
			frags := []EvidenceFragment{
				{Type: "memory_alloc", Role: "source", Detail: fmt.Sprintf("allocation of %s%s in function %s at line %d", c.VariableName, allocAPI, c.FunctionName, c.Line)},
			}
			if c.DefiniteLeak {
				frags = append(frags, EvidenceFragment{Type: "definite", Role: "condition", Detail: "no free, escape, or ownership transfer is reachable on any path from the allocation to function exit"})
			} else {
				frags = append(frags, EvidenceFragment{Type: "conditional", Role: "condition", Detail: "released/escaped/transferred on some paths but potentially leaked on others — trace each error/early-return path for a missing free"})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}
