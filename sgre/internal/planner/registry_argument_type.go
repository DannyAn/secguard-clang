package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "argument-type",
		CWE:               "CWE-686",
		SeedEventType:     "ARGUMENT_TYPE_MISMATCH",
		EvidenceType:      "ARGUMENT_TYPE_MISMATCH",
		DefaultSuspicion:  "suspected",
		FilterChain:       "default",
		FilterFactories:    chainDefault(),
		BuildVerdictFacts: buildArgumentTypeVerdictFacts,
		// An incompatible pointer cast is evidence of a type reinterpretation,
		// but an explicit cast is not proof of a defect (it can be an intentional
		// ABI/opaque boundary), so the AI agent judges intent rather than the
		// pipeline auto-confirming a cast.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "argument_type_mismatch", Role: "sink", Detail: fmt.Sprintf("call to %s passes %s as %s at line %d in function %s", c.APIName, c.ActualType, c.ExpectedType, c.Line, c.FunctionName)},
			}
			if c.CastType != "" {
				frags = append(frags, EvidenceFragment{Type: "explicit_cast", Role: "source", Detail: fmt.Sprintf("explicit cast %s reinterprets object %s (%s)", c.CastType, c.VariableName, c.ActualType)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildArgumentTypeVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 3)
	if c.ExpectedType != "" {
		facts = append(facts, VerdictFact{
			Token:  "expected@" + c.ExpectedType,
			Detail: fmt.Sprintf("the callee declares the parameter as %s", c.ExpectedType),
		})
	}
	if c.ActualType != "" {
		facts = append(facts, VerdictFact{
			Token:  "actual@" + c.ActualType,
			Detail: fmt.Sprintf("the argument is actually %s before any cast", c.ActualType),
		})
	}
	if c.CastType != "" {
		facts = append(facts, VerdictFact{
			Token:  "cast@" + c.CastType,
			Detail: fmt.Sprintf("an explicit cast to %s bridges the mismatch — judge whether it is an intentional ABI/opaque boundary or a papered-over reinterpretation", c.CastType),
		})
	}
	return facts
}
