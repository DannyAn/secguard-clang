package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "invalid-free",
		CWE:              "CWE-761",
		LegacyCWEs:       []string{"CWE-762"},
		SeedEventType:    "INVALID_FREE",
		EvidenceType:     "INVALID_FREE",
		DefaultSuspicion: "confirmed",
		FilterChain:      "default",
		FilterFactories:  chainDefault(),
		// Every shape is AST/alias-proved: the deallocator argument is a stack
		// object, a global array, or an interior pointer whose base is proven
		// non-heap (or a malloc base at an offset). The detector never reports
		// the ambiguous `free(ptr)` (a pointer value), so "confirmed" is sound
		// here — there is no heuristic tier for this type.
		BuildVerdictFacts: buildInvalidFreeVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{{
				Type:   "invalid_free",
				Role:   "sink",
				Detail: fmt.Sprintf("deallocator call on a %s object %s in %s at line %d", c.PointeeKind, c.VariableName, c.FunctionName, c.Line),
			}}
			if c.BaseOrigin != "" {
				frags = append(frags, EvidenceFragment{Type: "heap_base", Role: "source", Detail: fmt.Sprintf("the offset pointer's heap base was allocated at %s", c.BaseOrigin)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildInvalidFreeVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 3)
	if c.PointeeKind != "" {
		facts = append(facts, VerdictFact{
			Token:  "pointee@" + c.PointeeKind,
			Detail: fmt.Sprintf("the deallocator argument is a %s object — the pipeline proved it is NOT a heap base pointer (a stack/global object or an interior pointer), so the free is invalid", c.PointeeKind),
		})
	}
	if c.BaseOrigin != "" {
		facts = append(facts, VerdictFact{
			Token:  "base@" + c.BaseOrigin,
			Detail: "the offset pointer's heap base allocation site — the free releases an interior pointer, not the base the allocator returned",
		})
	}
	facts = append(facts, VerdictFact{
		Token:  fmt.Sprintf("free@%d", c.Line),
		Detail: fmt.Sprintf("the deallocator call site at line %d", c.Line),
	})
	return facts
}
