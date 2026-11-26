package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "switch-fallthrough",
		CWE:              "CWE-484",
		SeedEventType:    "SWITCH_FLOW",
		EvidenceType:     "SWITCH_FLOW",
		DefaultSuspicion: "suspected",
		FilterFactories:  chainDefault(),
		// Both shapes are heuristics, never auto-confirmed: an intentional
		// fallthrough and a deliberately-open enum switch are common idioms that
		// only the AI can separate from a defect by judging whether the two cases
		// (or the missing member) are independent semantic actions.
		Categories: []string{"fallthrough", "missing_default"},
		CategoryCWEs: map[string]string{
			"fallthrough":     "CWE-484",
			"missing_default": "CWE-478",
		},
		BuildVerdictFacts: buildSwitchFallthroughVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			detail := fmt.Sprintf("switch case in %s falls through at line %d", c.FunctionName, c.Line)
			if c.Category == "missing_default" {
				switch {
				case c.EnumCoverage != "":
					detail = fmt.Sprintf("switch on enum %s in %s at line %d does not cover every enumerator and has no default", c.EnumCoverage, c.FunctionName, c.Line)
				case c.Reason == "loop_progress":
					detail = fmt.Sprintf("switch in %s at line %d updates loop-progress variable(s) %s with no effective default — an unhandled value can stall the loop", c.FunctionName, c.Line, c.StateVars)
				default:
					detail = fmt.Sprintf("switch in %s at line %d dispatches with no effective default and writes state variable(s) %s consumed downstream", c.FunctionName, c.Line, c.StateVars)
				}
			}
			frags := []EvidenceFragment{{Type: "switch_flow", Role: "sink", Detail: detail}}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildSwitchFallthroughVerdictFacts(c Candidate) []VerdictFact {
	if c.Category == "missing_default" {
		facts := make([]VerdictFact, 0, 4)
		if c.EnumCoverage != "" {
			facts = append(facts, VerdictFact{
				Token:  "enum@" + c.EnumCoverage,
				Detail: "the switch condition is an enum type and not every enumerator is covered, with no default — judge whether the uncovered members are unreachable (dismiss) or a real missing-handler gap (confirm)",
			})
		}
		if c.Reason != "" {
			facts = append(facts, VerdictFact{
				Token:  "unhandled@" + c.Reason,
				Detail: switchReasonDetail(c.Reason),
			})
		}
		if c.StateVars != "" {
			facts = append(facts, VerdictFact{
				Token:  "state@" + c.StateVars,
				Detail: "the variables the switch writes that are read after it — an unhandled value leaves them stale/unset, so judge whether that value can actually reach the switch",
			})
		}
		if c.DefaultKind != "" {
			facts = append(facts, VerdictFact{
				Token:  "default@" + c.DefaultKind,
				Detail: "how the switch handles an unknown value — an empty or absent default does not handle it, so judge whether upstream validation already makes it unreachable",
			})
		}
		return facts
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

func switchReasonDetail(reason string) string {
	switch reason {
	case "enum_gap":
		return "the switch condition is an enum and not every non-sentinel enumerator is covered, with no default — an uncovered enumerator is unhandled"
	case "loop_progress":
		return "the switch updates a variable the enclosing loop's continuation reads — a missing case can leave it stale and stall the loop (CWE-478 root cause of a possible CWE-835 non-progress)"
	case "unhandled_state":
		return "the switch dispatches on a state/status/type/error selector and writes a variable consumed downstream, with no effective default — an unhandled value leaves that state stale or unset"
	default:
		return "the switch does not effectively handle an unknown value"
	}
}
