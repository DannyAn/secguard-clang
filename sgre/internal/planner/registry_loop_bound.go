package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "loop-bound",
		CWE:              "CWE-834",
		SeedEventType:    "LOOP_BOUND",
		EvidenceType:     "LOOP_BOUND",
		DefaultSuspicion: "suspected",
		FilterFactories:  chainDefault(),
		Categories:       []string{"unchecked_input_bound", "bound_mul"},
		CategoryCWEs: map[string]string{
			"unchecked_input_bound": "CWE-606",
			"bound_mul":             "CWE-834",
		},
		BuildVerdictFacts: buildLoopBoundVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			detail := fmt.Sprintf("a %s loop in %s at line %d is bounded by %s (%s), which is not statically bounded",
				c.LoopKind, c.FunctionName, c.Line, c.LoopBound, c.LoopBoundKind)
			if c.Category == "bound_mul" {
				detail = fmt.Sprintf("a %s loop in %s at line %d is bounded by the product %s — an overflow-prone iteration-count computation",
					c.LoopKind, c.FunctionName, c.Line, c.LoopBound)
			}
			frags := []EvidenceFragment{{Type: "loop_bound", Role: "sink", Detail: detail}}
			if c.LoopVar != "" {
				frags = append(frags, EvidenceFragment{Type: "loop_bound", Role: "condition", Detail: fmt.Sprintf("the loop induction variable is `%s`", c.LoopVar)})
			}
			if c.Origin != "" {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: fmt.Sprintf("the loop bound originates at %s", c.Origin)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildLoopBoundVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	if c.LoopKind != "" {
		facts = append(facts, VerdictFact{
			Token:  "loop-kind@" + c.LoopKind,
			Detail: fmt.Sprintf("the loop construct is `%s`", c.LoopKind),
		})
	}
	if c.LoopVar != "" {
		facts = append(facts, VerdictFact{
			Token:  "loop-var@" + c.LoopVar,
			Detail: fmt.Sprintf("the induction variable is `%s` (the LHS of the ascending condition)", c.LoopVar),
		})
	}
	if c.LoopBound != "" {
		facts = append(facts, VerdictFact{
			Token:  "loop-bound@" + c.LoopBound,
			Detail: fmt.Sprintf("the loop's upper bound is `%s` — the value that controls the iteration count", c.LoopBound),
		})
	}
	if c.Category == "unchecked_input_bound" {
		facts = append(facts, VerdictFact{
			Token:  "bound-src@" + c.LoopBoundKind,
			Detail: fmt.Sprintf("the bound originates from a %s — it is not statically bounded; judge whether the caller/source can supply a large value (confirm CWE-606) or a business/protocol constraint bounds it (dismiss)", c.LoopBoundKind),
		})
		facts = append(facts, VerdictFact{
			Token:  "guard@none-upper",
			Detail: "no upper-bound check or clamp dominates the loop (the detector already skipped guarded/clamped loops)",
		})
	} else {
		facts = append(facts, VerdictFact{
			Token:  "loop-bound@" + c.LoopBound,
			Detail: fmt.Sprintf("the bound is the product `%s` — an overflow-prone iteration-count computation (CWE-190 root cause); judge whether the operands can be large enough to overflow or to drive excessive iteration (confirm CWE-834) or are bounded by contract (dismiss)", c.LoopBound),
		})
	}
	return facts
}
