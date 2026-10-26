package planner

import (
	"fmt"
	"path/filepath"
	"strings"
)

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "path-traversal",
		CWE:               "CWE-22",
		SeedEventType:     "PATH_TRAVERSAL",
		EvidenceType:      "PATH_TRAVERSAL",
		DefaultSuspicion:  "suspected",
		FilterChain:       "path-traversal",
		FilterFactories:   chainTaint(),
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
			if len(c.CallsiteSites) > 0 {
				frags = append(frags, EvidenceFragment{Type: "callsite_list", Role: "caller", Detail: "concrete in-tree call sites (file:line — class): " + renderCallSiteList(c.CallsiteSites)})
			}
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: taintSourceDetail(c, "the path argument")})
			}
			return frags
		},
	})
}

func buildPathTraversalVerdictFacts(c Candidate) []VerdictFact {
	if c.PathExpr == "" {
		return nil
	}
	facts := []VerdictFact{{
		Token:  "path-arg@" + c.PathExpr,
		Detail: fmt.Sprintf("the path argument is `%s` — the traversal root; judge whether a caller can inject `../` segments", c.PathExpr),
	}}
	if c.CallsiteSummary != "" {
		facts = append(facts, VerdictFact{
			Token:  "callsites@" + c.CallsiteSummary,
			Detail: fmt.Sprintf("in-tree call-site census for the path parameter: %s — all-literal callers pass compile-time constants (dismiss); the var/tainted callers are where attacker input could enter (inspect them)", expandCallsiteFact(c.CallsiteSummary)),
		})
	}
	return facts
}

// renderCallSiteList renders the bounded per-site breakdown as a single-line,
// grep-free caller list: "literal@fc_fwd.c:108, variable@carnat_fc_fwd.c:272".
func renderCallSiteList(sites []CallSiteInfo) string {
	parts := make([]string, 0, len(sites))
	for _, s := range sites {
		parts = append(parts, fmt.Sprintf("%s@%s:%d", s.Class, filepath.Base(s.File), s.Line))
	}
	return strings.Join(parts, ", ")
}
