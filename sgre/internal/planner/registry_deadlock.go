package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "deadlock",
		CWE:              "CWE-667",
		SeedEventType:    "DEADLOCK",
		EvidenceType:     "DEADLOCK",
		DefaultSuspicion: "suspected",
		FilterChain:      "deadlock",
		FilterFactories:    chainDeadlock(),
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "deadlock", Role: "sink", Detail: fmt.Sprintf("lock-order inversion (potential deadlock) in %s at line %d", c.FunctionName, c.Line)},
			}
			if c.MutexA != "" && c.MutexB != "" {
				frags = append(frags, EvidenceFragment{Type: "lock_pair", Role: "condition", Detail: fmt.Sprintf("this function locks %s then %s", c.MutexA, c.MutexB)})
			}
			if c.ReverseFunc != "" {
				frags = append(frags, EvidenceFragment{Type: "reverse_order", Role: "source", Detail: fmt.Sprintf("function %s acquires the same locks in the opposite order", c.ReverseFunc)})
			}
			return frags
		},
	})
}
