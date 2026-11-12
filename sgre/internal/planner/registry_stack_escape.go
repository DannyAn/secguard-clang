package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "stack-address-escape",
		CWE:              "CWE-562",
		SeedEventType:    "STACK_ESCAPE",
		EvidenceType:     "STACK_ESCAPE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		FilterFactories:  chainDefault(),
		// Returning the address of a non-static local (or a decayed local
		// array) is AST-deterministic: the operand is provably in the returning
		// function's own frame, so the returned pointer is certain CWE-562. The
		// store and async-arg shapes only prove the address reaches a live
		// location, not that the target outlives the frame, so they stay
		// suspected for the AI to judge the lifetime.
		//
		// The _opaque variant is the issue #263 downgrade: the base's declared
		// type is an opaque typedef, so the detector cannot prove whether
		// `&q->f` addresses this frame (a local aggregate) or the pointee (a
		// hidden pointer typedef). Auto-confirming that shape produced false
		// positives; it goes to the AI as a suspected lead instead.
		CategoryConfidence: map[string]string{
			"return_stack_address":        "confirmed",
			"return_stack_address_opaque": "suspected",
			"escape_via_store":            "suspected",
			"escape_via_async_arg":        "suspected",
		},
		BuildVerdictFacts: buildStackEscapeVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{{
				Type:   "stack_escape",
				Role:   "sink",
				Detail: fmt.Sprintf("address of local %s escapes via %s in %s at line %d", c.VariableName, escapeKindLabel(c.Category), c.FunctionName, c.Line),
			}}
			if c.Origin != "" {
				frags = append(frags, EvidenceFragment{Type: "declaration", Role: "source", Detail: fmt.Sprintf("the local %s origin (declaration-line:escape-line) is %s", c.VariableName, c.Origin)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func escapeKindLabel(category string) string {
	switch category {
	case "return_stack_address":
		return "return"
	case "return_stack_address_opaque":
		return "return-opaque"
	case "escape_via_store":
		return "store"
	case "escape_via_async_arg":
		return "async-arg"
	}
	return category
}

// staticHintValue maps the detector's storage class ("auto"/"static") to the
// `static@no|yes` hint value: the hint states whether the local IS static, not
// its storage class spelling.
func staticHintValue(storage string) string {
	if storage == "static" {
		return "yes"
	}
	return "no"
}

func buildStackEscapeVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 3)
	if c.VariableName != "" {
		facts = append(facts, VerdictFact{
			Token:  "object@" + c.VariableName,
			Detail: fmt.Sprintf("the non-static local `%s` whose address escapes", c.VariableName),
		})
	}
	if c.Storage != "" {
		facts = append(facts, VerdictFact{
			Token:  "static@" + staticHintValue(c.Storage),
			Detail: "storage class is auto (not static) — a static local's storage outlives the frame, so the pipeline would NOT have reported it; the address genuinely escapes",
		})
	}
	if c.Category != "" {
		facts = append(facts, VerdictFact{
			Token:  "escape-kind@" + escapeKindLabel(c.Category),
			Detail: fmt.Sprintf("the escape channel: %s (return = certain dangling pointer; return-opaque = the base's declared type is an opaque typedef, so the pipeline could not prove the address lands in this frame and left the judgment to the AI; store/async-arg = the address reaches a live location, judge whether that location outlives the frame)", escapeKindLabel(c.Category)),
		})
	}
	if c.BaseKind != "" {
		facts = append(facts, VerdictFact{
			Token:  "base-kind@" + c.BaseKind,
			Detail: fmt.Sprintf("the local's declared-type shape is %s — a pointer/typedef_pointer base means `&q->f` addresses the POINTEE (not this frame); a struct/union/scalar base means it addresses the local object in this frame; an opaque base is a typedef whose target the scan tree cannot see", c.BaseKind),
		})
	}
	return facts
}
