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
		BuildVerdictFacts: buildDeadlockVerdictFacts,
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

func buildDeadlockVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	if c.MutexA != "" && c.MutexB != "" {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("lock@%s-%s", c.MutexA, c.MutexB),
			Detail: fmt.Sprintf("lock-order cycle between %s and %s (LOCK_ORDER graph edge)", c.MutexA, c.MutexB),
		})
	}
	if c.ReverseFunc != "" {
		facts = append(facts, VerdictFact{
			Token:  "reverse@" + c.ReverseFunc,
			Detail: "the reverse-order acquirer: " + c.ReverseFunc + " acquires the two locks in the opposite order",
		})
	}
	return facts
}
