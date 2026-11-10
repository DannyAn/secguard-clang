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
		FilterFactories:   chainMemoryLeak(),
		BuildVerdictFacts: buildLeakVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			// Global-container shallow free (issue #255): the leaked block is
			// not the candidate line's allocation. Its only referent is the
			// field of an object the global container owns; the deletion path
			// released the object without releasing the field and then cleared
			// the slot. The fragments carry the whole chain because the three
			// functions involved (create, wrapper store, delete) never appear
			// in one Code Context window.
			if c.LeakChain != "" {
				allocAPI := c.APIName
				if allocAPI == "" {
					allocAPI = "an allocator"
				}
				allocDetail := fmt.Sprintf("`%s` (an object field of `%s`) is allocated via %s", c.VariableName, c.LeakObject, allocAPI)
				if c.LeakFieldAlloc != "" {
					allocDetail += fmt.Sprintf(" at %s", c.LeakFieldAlloc)
				}
				if c.LeakFieldStore != "" {
					allocDetail += fmt.Sprintf(", and the object field is attached by the store at %s", c.LeakFieldStore)
				}
				releaseDetail := fmt.Sprintf("the deletion path `%s` releases the outer object", c.FunctionName)
				if c.LeakShallowFree != "" {
					releaseDetail += fmt.Sprintf(" via `%s`", c.LeakShallowFree)
				}
				releaseDetail += fmt.Sprintf(" but never releases `%s`; clearing the container slot at line %d drops the last reference", c.VariableName, c.Line)
				return []EvidenceFragment{
					{Type: "memory_alloc", Role: "source", Detail: allocDetail},
					{Type: "ref_chain", Role: "path", Detail: fmt.Sprintf("the leaked block is reachable only through %s", c.LeakChain)},
					{Type: "shallow_release", Role: "sink", Detail: releaseDetail},
					{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
				}
			}
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
