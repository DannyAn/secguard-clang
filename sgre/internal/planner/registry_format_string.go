package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "format-string",
		CWE:               "CWE-134",
		SeedEventType:     "FORMAT_STRING",
		EvidenceType:      "FORMAT_STRING_VULN",
		DefaultSuspicion:  "suspected",
		FilterChain:       "format-string",
		FilterFactories:    chainTaint(),
		BuildVerdictFacts: buildFormatStringVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "format_string", Role: "sink", Detail: fmt.Sprintf("printf-family called with non-literal format in %s at line %d", c.FunctionName, c.Line)},
			}
			if c.APIName != "" {
				frags = append(frags, EvidenceFragment{Type: "api", Role: "sink", Detail: fmt.Sprintf("format function: %s", c.APIName)})
			}
			if c.FormatArg != "" {
				frags = append(frags, EvidenceFragment{Type: "format_arg", Role: "condition", Detail: fmt.Sprintf("format argument: %s", c.FormatArg)})
			}
			if c.CallsiteSummary != "" {
				frags = append(frags, EvidenceFragment{Type: "callsite_census", Role: "caller", Detail: fmt.Sprintf("in-tree call sites for the format parameter: %s — all-literal means every caller passes a compile-time constant; the var/tainted entries are the callers where attacker input could enter", expandCallsiteFact(c.CallsiteSummary))})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: taintSourceDetail(c, "the format argument")})
			}
			return frags
		},
	})
}

func buildFormatStringVerdictFacts(c Candidate) []VerdictFact {
	if c.FormatArg == "" {
		return nil
	}
	facts := []VerdictFact{{
		Token:  "fmt-arg@" + c.FormatArg,
		Detail: fmt.Sprintf("the format argument is `%s` — attacker-controlled (paired with tainted) means arbitrary format-specifier injection; a constant literal means dismissed", c.FormatArg),
	}}
	if c.CallsiteSummary != "" {
		facts = append(facts, VerdictFact{
			Token:  "callsites@" + c.CallsiteSummary,
			Detail: fmt.Sprintf("in-tree call-site census for the format parameter: %s — all-literal callers pass compile-time constants (dismiss); the var/tainted callers are where attacker input could enter (inspect them)", expandCallsiteFact(c.CallsiteSummary)),
		})
	}
	return facts
}
