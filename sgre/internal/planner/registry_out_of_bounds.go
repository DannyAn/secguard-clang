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
		// The unchecked-external-index read family (a fixed-size array read
		// through a struct field with no in-code bounds check) shares ONE
		// external-bound judgment per (file, index-source field, capacity,
		// access flavor): the AI decides once whether the field's range is
		// externally guaranteed (config model / CLI range) and the folded sites
		// stay listed.
		ShapeKey:   externalIndexShapeKey,
		Categories: []string{"array_oob_read", "heap_oob_read", "array_oob_read_unchecked", "layout_oob_read"},
		// A read-flavored OOB is only emitted when the detector proved the
		// index outruns the array/allocation, so it is confirmed, not suspected.
		// layout_oob_read is suspected: its proof depends on a Type Layout
		// census whose provenance is assumed_default_abi in Phase 1 (no
		// compile_commands wiring), so the layout sizes are not ABI-proven.
		CategoryConfidence: map[string]string{
			"array_oob_read":           "confirmed",
			"heap_oob_read":            "confirmed",
			"array_oob_read_unchecked": "suspected",
			"layout_oob_read":          "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			if c.Category == "layout_oob_read" {
				frags := []EvidenceFragment{
					{Type: "out_of_bounds", Role: "sink", Detail: fmt.Sprintf("layout out-of-bounds read in function %s at line %d", c.FunctionName, c.Line)},
					{Type: "struct_layout", Role: "sink", Detail: fmt.Sprintf("cast target: struct %s, allocation %d bytes", c.StructType, c.AllocSize)},
					{Type: "field_access", Role: "sink", Detail: fmt.Sprintf("field %s at offset %d (size %d) — access end %d exceeds the allocation", c.Index, c.FieldOffset, c.FieldSize, c.FieldOffset+c.FieldSize)},
				}
				frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
				return frags
			}
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
				frags = append(frags, EvidenceFragment{Type: "external_bound", Role: "condition", Detail: fmt.Sprintf("the upper bound of index source %s is NOT provable in code; if an external model (config schema / CLI value range / protocol) guarantees the field's range, the disposition is a PENDING EXTERNAL CONSTRAINT to confirm outside the code rather than a proven out-of-bounds read", c.IndexSource)})
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
			if len(c.ClusterSites) > 0 {
				frags = append(frags, EvidenceFragment{Type: "shape_cluster", Role: "scope", Detail: fmt.Sprintf("the same unchecked external-index shape (index source %s, capacity %d) repeats at %d other site(s) in this file — one external-bound judgment covers the whole group; the sites are listed under `## Clustered Sites`", c.IndexSource, c.Size, len(c.ClusterSites))})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			frags = append(frags, bufferFlowSteps(c)...)
			return frags
		},
	})
}
