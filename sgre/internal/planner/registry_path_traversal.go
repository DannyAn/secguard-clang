package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "path-traversal",
		CWE:               "CWE-22",
		SeedEventType:     "PATH_TRAVERSAL",
		EvidenceType:      "PATH_TRAVERSAL",
		DefaultSuspicion:  "suspected",
		FilterChain:       "path-traversal",
		FilterFactories:    chainTaint(),
		BuildVerdictFacts: buildPathTraversalVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "path_traversal", Role: "sink", Detail: fmt.Sprintf("filesystem call %s receives a path that is not a fixed string literal — an attacker-controlled value could use ../ to escape the intended directory and read/overwrite/delete an arbitrary file", c.APIName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			if c.PathExpr != "" {
				frags = append(frags, EvidenceFragment{Type: "path_arg", Role: "condition", Detail: fmt.Sprintf("path argument: %s", c.PathExpr)})
			}
			if c.CallsiteSummary != "" {
				frags = append(frags, EvidenceFragment{Type: "callsite_census", Role: "caller", Detail: fmt.Sprintf("in-tree call sites for the path parameter: %s — all-literal means every caller passes a compile-time constant; the var/tainted entries are the callers where attacker input could enter", expandCallsiteFact(c.CallsiteSummary))})
			}
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: taintSourceDetail(c, "the path argument")})
			}
			return frags
		},
	})
}
