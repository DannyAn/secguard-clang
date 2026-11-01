package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "switch-fallthrough",
		CWE:              "CWE-484",
		SeedEventType:    "SWITCH_FLOW",
		EvidenceType:     "SWITCH_FLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		FilterFactories:  chainDefault(),
		// Both shapes are heuristics, never auto-confirmed: an intentional
		// fallthrough and a deliberately-open enum switch are common idioms that
		// only the AI can separate from a defect by judging whether the two cases
		// (or the missing member) are independent semantic actions.
		Categories: []string{"fallthrough", "missing_default"},
		CategoryCWEs: map[string]string{
			"fallthrough":    "CWE-484",
			"missing_default": "CWE-478",
		},
		BuildVerdictFacts: buildSwitchFallthroughVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			detail := fmt.Sprintf("switch case in %s falls through at line %d", c.FunctionName, c.Line)
			if c.Category == "missing_default" {
				detail = fmt.Sprintf("switch on enum %s in %s at line %d does not cover every enumerator and has no default", c.EnumCoverage, c.FunctionName, c.Line)
			}
			frags := []EvidenceFragment{{Type: "switch_flow", Role: "sink", Detail: detail}}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildSwitchFallthroughVerdictFacts(c Candidate) []VerdictFact {
	if c.Category == "missing_default" {
		return []VerdictFact{{
			Token:  "enum@" + c.EnumCoverage,
			Detail: "the switch condition is an enum type and not every enumerator is covered, with no default — judge whether the uncovered members are unreachable (dismiss) or a real missing-handler gap (confirm)",
		}}
	}
	facts := make([]VerdictFact, 0, 3)
	facts = append(facts, VerdictFact{Token: "fall@yes", Detail: "the case body is non-empty and its last statement does not terminate — control falls into the next case"})
	facts = append(facts, VerdictFact{Token: "comment@none", Detail: "no exemption comment (`fall through` / `fallthrough`) sits between this case and the next — the pipeline already suppressed the documented-intent cases"})
	if c.CaseEnd != "" {
		facts = append(facts, VerdictFact{
			Token:  "case_end@" + c.CaseEnd,
			Detail: fmt.Sprintf("the case's last statement kind is %s — it does not break/return/goto, so the fallthrough is structural", c.CaseEnd),
		})
	}
	return facts
}
