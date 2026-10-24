package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "use-after-free",
		CWE:              "CWE-416",
		SeedEventType:    "USE_AFTER_FREE",
		EvidenceType:     "USE_AFTER_FREE",
		DefaultSuspicion: "suspected",
		FilterChain:      "lifetime",
		FilterFactories:    chainLifetime(),
		// One freed variable used at many sites is one defect, not one per use.
		ConvergeByVariable: true,
		BuildVerdictFacts: buildUseAfterFreeVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "use_after_free", Role: "sink", Detail: fmt.Sprintf("variable %s freed at line %d then used at line %d in function %s", c.VariableName, c.FreeLine, c.Line, c.FunctionName)},
			}
			if c.FreeLine > 0 {
				detail := fmt.Sprintf("free(%s) at line %d", c.VariableName, c.FreeLine)
				if c.MayFree {
					via := c.CalleeName
					if via == "" {
						via = "a release helper"
					}
					detail = fmt.Sprintf("release at line %d via %s, which frees the object only on some paths (may-free)", c.FreeLine, via)
				}
				frags = append(frags, EvidenceFragment{Type: "free_site", Role: "source", Detail: detail})
			}
			if c.MayFree {
				frags = append(frags, EvidenceFragment{Type: "may_free", Role: "condition", Detail: "the release is conditional (the release helper frees only on some paths), so this is a POSSIBLE use-after-free — confirm only if the release and the use can both execute on one path"})
			}
			frags = append(frags, EvidenceFragment{Type: "use_site", Role: "sink", Detail: fmt.Sprintf("use of %s at line %d", c.VariableName, c.Line)})
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"Use of a pointer after it has been freed is a real defect",
			"The pipeline tracks freed-state through the CFG",
		},
		RequiredEvidence: []string{"free location", "use location", "path from free to use"},
		KnownLimitations: []string{
			"Pointer aliasing may cause missed freed-state propagation",
			"Cross-function free→use is not fully tracked",
		},
	})
}

func buildUseAfterFreeVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	if c.FreeLine > 0 {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("free@%d", c.FreeLine),
			Detail: fmt.Sprintf("the free site line: %d", c.FreeLine),
		})
	}
	if c.Category != "" {
		facts = append(facts, VerdictFact{
			Token:  "cat@" + c.Category,
			Detail: "detector category: " + c.Category + " (use_after_free / double_free)",
		})
	}
	if c.MayFree {
		facts = append(facts, VerdictFact{
			Token:  "may-free",
			Detail: "the release is conditional (a release helper frees only on some paths) — the verdict is possible, not proved",
		})
	}
	return facts
}
