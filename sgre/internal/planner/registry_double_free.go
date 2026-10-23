package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "double-free",
		CWE:               "CWE-415",
		SeedEventType:     "DOUBLE_FREE",
		EvidenceType:      "DOUBLE_FREE",
		DefaultSuspicion:  "suspected",
		FilterChain:       "double-free",
		BuildVerdictFacts: buildDoubleFreeVerdictFacts,
		// One variable freed twice is one defect, not one per (first,second) pair.
		ConvergeByVariable: true,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "double_free", Role: "sink", Detail: fmt.Sprintf("variable %s freed twice in function %s", c.VariableName, c.FunctionName)},
			}
			if c.FirstFree > 0 {
				detail := fmt.Sprintf("first free(%s) at line %d", c.VariableName, c.FirstFree)
				if c.MayFree {
					via := c.FirstCallee
					if via == "" {
						via = "a release helper"
					}
					detail = fmt.Sprintf("first release at line %d via %s%s, which frees the object only on some paths (may-free)", c.FirstFree, via, victimSuffix(c.Victims))
				} else if c.FirstCallee != "" {
					detail = fmt.Sprintf("first free via %s on %s at line %d", c.FirstCallee, c.VariableName, c.FirstFree)
				}
				frags = append(frags, EvidenceFragment{Type: "first_free", Role: "source", Detail: detail})
			}
			secondFree := c.SecondFree
			if secondFree == 0 {
				secondFree = c.Line
			}
			frags = append(frags, EvidenceFragment{Type: "second_free", Role: "sink", Detail: fmt.Sprintf("second free(%s) at line %d", c.VariableName, secondFree)})
			if c.MayFree {
				frags = append(frags, EvidenceFragment{Type: "may_free", Role: "condition", Detail: "the first release is conditional (the release helper frees only on some paths), so this is a POSSIBLE double free — confirm only if the two frees can both execute on one path"})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}
