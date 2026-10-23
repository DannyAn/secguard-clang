package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "buffer-overflow",
		CWE:               "CWE-787",
		SeedEventType:     "BUFFER_ACCESS",
		EvidenceType:      "BUFFER_OVERFLOW",
		DefaultSuspicion:  "suspected",
		FilterChain:       "buffer-overflow",
		BuildVerdictFacts: buildBufferVerdictFacts,
		Categories:        []string{"buffer_overflow", "array_oob_write", "heap_oob_write", "array_oob_write_unchecked", "format_overflow", "format_overflow_var", "bounded_copy_overflow", "bounded_copy_var_size", "secure_copy_overflow", "secure_copy_var_size", "secure_constraint_violation", "secure_scanf_overflow", "secure_scanf_var_size"},
		// Provable out-of-bounds writes (a constant index past a known array or
		// allocation size, a constant copy size exceeding a known capacity, or
		// an Annex K `_s` function given a lying destination-capacity argument)
		// are confirmed by the detector itself; an unguarded unsafe call or
		// sprintf remains a heuristic suspicion. A variable copy size / capacity
		// that is caller-influenced is tiered to "possible", and a proven
		// `_s` constraint violation (required > declared capacity, no actual
		// overflow) is "suspected" — the AI agent weighs the handler's behavior.
		CategoryConfidence: map[string]string{
			"array_oob_write":             "confirmed",
			"heap_oob_write":              "confirmed",
			"array_oob_write_unchecked":   "suspected",
			"bounded_copy_overflow":       "confirmed",
			"bounded_copy_var_size":       "possible",
			"secure_copy_overflow":        "confirmed",
			"secure_copy_var_size":        "possible",
			"secure_constraint_violation": "suspected",
			"secure_scanf_overflow":       "confirmed",
			"secure_scanf_var_size":       "possible",
			"format_overflow":             "confirmed",
			"format_overflow_var":         "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "buffer_access", Role: "sink", Detail: fmt.Sprintf("buffer access in function %s at line %d", c.FunctionName, c.Line)},
			}
			if c.APIName != "" {
				frags = append(frags, EvidenceFragment{Type: "api", Role: "sink", Detail: fmt.Sprintf("unsafe API: %s", c.APIName)})
			}
			if c.Array != "" {
				frags = append(frags, EvidenceFragment{Type: "buffer", Role: "sink", Detail: fmt.Sprintf("buffer: %s (capacity: %d elements)", c.Array, c.Size)})
			}
			if c.Index != "" {
				frags = append(frags, EvidenceFragment{Type: "index", Role: "condition", Detail: fmt.Sprintf("access index/copy size: %s", c.Index)})
			}
			if c.IndexSource != "" {
				frags = append(frags, EvidenceFragment{Type: "index_source", Role: "condition", Detail: fmt.Sprintf("index source: struct field %s — no bounds check against the array's capacity dominates this access", c.IndexSource)})
			}
			if c.ElemField != "" {
				frags = append(frags, EvidenceFragment{Type: "element_field", Role: "sink", Detail: fmt.Sprintf("pointer member read from the indexed element: %s", c.ElemField)})
			}
			if c.Escape != "" {
				frags = append(frags, EvidenceFragment{Type: "escape", Role: "sink", Detail: fmt.Sprintf("the element (or its address) escapes to %s", c.Escape)})
			}
			if c.CopySize != "" {
				frags = append(frags, EvidenceFragment{Type: "copy_size", Role: "condition", Detail: fmt.Sprintf("copy size: %s", c.CopySize)})
			}
			if c.DstCapacity != "" {
				frags = append(frags, EvidenceFragment{Type: "dst_capacity", Role: "condition", Detail: fmt.Sprintf("destination capacity: %s", c.DstCapacity)})
			}
			if c.SizeArgument != "" {
				frags = append(frags, EvidenceFragment{Type: "size_argument", Role: "condition", Detail: fmt.Sprintf("_s size argument: %s", c.SizeArgument)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"A write past the end of a buffer is a real defect",
			"Constant indices/sizes past known bounds are confirmed by the detector",
		},
		RequiredEvidence: []string{"buffer allocation size", "access index or copy size", "bound check absence"},
		KnownLimitations: []string{
			"Variable indices/sizes require caller-influence analysis",
			"Byte vs element unit confusion may cause false positives",
		},
	})
}
