package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "sizeof-misuse",
		CWE:               "CWE-467",
		SeedEventType:     "SIZEOF_MISUSE",
		EvidenceType:      "SIZEOF_MISUSE",
		DefaultSuspicion:  "suspected",
		FilterChain:       "default",
		BuildVerdictFacts: buildSizeofMisuseVerdictFacts,
		Categories:        []string{"sizeof_pointer", "sizeof_pointer_ambig"},
		// `sizeof(p)` on a single-level pointer `T *p` is provably the pointer
		// width where the object size is intended (CWE-467) — confirmed. A
		// pointer-to-pointer `T **p` is legitimately sized by `sizeof(p)` when
		// allocating an array of pointers, so it stays suspected.
		CategoryConfidence: map[string]string{
			"sizeof_pointer":       "confirmed",
			"sizeof_pointer_ambig": "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "sizeof_misuse", Role: "sink", Detail: fmt.Sprintf("sizeof applied to pointer variable %s in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}
