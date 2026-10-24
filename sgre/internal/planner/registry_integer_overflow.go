package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "integer-overflow",
		CWE:              "CWE-190",
		SeedEventType:    "INTEGER_OVERFLOW",
		EvidenceType:     "INTEGER_OVERFLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "integer-overflow",
		FilterFactories:    chainIntegerOverflow(),
		// Value-analysis tiers. size_calc_overflow (malloc(a * b) / malloc(n *
		// sizeof(T))) and size_mul_const_overflow (malloc(n * CONST), CONST >= 256
		// and n caller-influenced) are concrete CWE-190 patterns and stay
		// "suspected". The wraparound-in-a-bounds-check pattern (integer_overflow)
		// is a theoretical wraparound and is "possible". Addition/subtraction
		// on size operands (n + 1 / n - 1) is not emitted — null-terminator /
		// off-by-one noise. An unsigned subtraction passed to an ordinary call is
		// kept as suspected: it has a concrete underflow path unless guarded.
		CategoryConfidence: map[string]string{
			"definite_overflow":       "confirmed",
			"size_calc_overflow":      "suspected",
			"size_mul_const_overflow": "suspected",
			"unsigned_sub_underflow":  "suspected",
			"integer_overflow":        "possible",
		},
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("integer-overflow:%d:%s:%d", c.FileID, c.FunctionName, c.Line)
		},
		BuildVerdictFacts: buildIntegerOverflowVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			detail := fmt.Sprintf("arithmetic overflow in size calculation in %s at line %d", c.FunctionName, c.Line)
			if c.Category == "unsigned_sub_underflow" {
				detail = fmt.Sprintf("unsigned subtraction can underflow before use in %s at line %d", c.FunctionName, c.Line)
			}
			frags := []EvidenceFragment{
				{Type: "integer_overflow", Role: "sink", Detail: detail},
			}
			if c.SubLHSInfluenced {
				frags = append(frags, EvidenceFragment{Type: "operand_influenced", Role: "source", Detail: "left operand is caller/attacker-controlled"})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildIntegerOverflowVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 5)
	if c.Category != "" {
		facts = append(facts, VerdictFact{
			Token:  "cat@" + c.Category,
			Detail: "detector category: " + c.Category + " (definite_overflow is literal-proved; the rest need interval/context)",
		})
	}
	if c.LHSKind != "" {
		influenced := "no"
		if c.SubLHSInfluenced {
			influenced = "yes (caller/attacker-controlled)"
		}
		facts = append(facts, VerdictFact{
			Token:  "lhs@" + c.LHSKind,
			Detail: fmt.Sprintf("left operand origin = %s, caller-influenced = %s", c.LHSKind, influenced),
		})
	}
	if c.RHSKind != "" {
		influenced := "no"
		if c.SubRHSInfluenced {
			influenced = "yes (caller/attacker-controlled)"
		}
		facts = append(facts, VerdictFact{
			Token:  "rhs@" + c.RHSKind,
			Detail: fmt.Sprintf("right operand origin = %s, caller-influenced = %s", c.RHSKind, influenced),
		})
	}
	if c.SubSink != "" {
		facts = append(facts, VerdictFact{
			Token:  "sink@" + c.SubSink,
			Detail: "sink shape: " + c.SubSink + " (call_arg = passed into an allocation / copy call, assign = stored into a variable)",
		})
	}
	return facts
}
