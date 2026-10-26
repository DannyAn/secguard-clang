package planner

import (
	"fmt"
	"strings"
)

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "out-of-bounds",
		CWE:               "CWE-125",
		SeedEventType:     "BUFFER_ACCESS",
		EvidenceType:      "OUT_OF_BOUNDS",
		DefaultSuspicion:  "suspected",
		FilterChain:       "buffer-overflow",
		FilterFactories:   chainBufferOverflow(),
		BuildVerdictFacts: buildBufferVerdictFacts,
		Categories:        []string{"array_oob_read", "heap_oob_read", "array_oob_read_unchecked"},
		// A read-flavored OOB is only emitted when the detector proved the
		// index outruns the array/allocation, so it is confirmed, not suspected.
		CategoryConfidence: map[string]string{
			"array_oob_read":           "confirmed",
			"heap_oob_read":            "confirmed",
			"array_oob_read_unchecked": "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "out_of_bounds", Role: "sink", Detail: fmt.Sprintf("out-of-bounds access in function %s at line %d", c.FunctionName, c.Line)},
			}
			if c.Array != "" {
				capacity := ""
				if c.Size > 0 {
					capacity = fmt.Sprintf(" (capacity: %d elements)", c.Size)
				}
				frags = append(frags, EvidenceFragment{Type: "buffer", Role: "sink", Detail: fmt.Sprintf("array: %s%s", c.Array, capacity)})
			}
			if c.Index != "" {
				frags = append(frags, EvidenceFragment{Type: "index", Role: "condition", Detail: fmt.Sprintf("access index: %s", c.Index)})
			}
			if c.IndexSource != "" {
				frags = append(frags, EvidenceFragment{Type: "index_source", Role: "condition", Detail: fmt.Sprintf("index source: struct field %s — no bounds check against the array's capacity dominates this access", c.IndexSource)})
			}
			if c.ElemField != "" {
				frags = append(frags, EvidenceFragment{Type: "element_field", Role: "sink", Detail: fmt.Sprintf("pointer member read from the indexed element: %s (indeterminate when the index is out of range)", c.ElemField)})
			}
			if c.Escape != "" {
				deref := ""
				if c.EscapeDeref != "" {
					deref = fmt.Sprintf(" and reads its pointer member %s", strings.SplitN(c.EscapeDeref, "@", 2)[0])
				}
				frags = append(frags, EvidenceFragment{Type: "escape", Role: "sink", Detail: fmt.Sprintf("the element (or its address) escapes to %s, which dereferences it%s — the OOB element feeds a null-deref sink", c.Escape, deref)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			frags = append(frags, bufferFlowSteps(c)...)
			return frags
		},
	})
}
