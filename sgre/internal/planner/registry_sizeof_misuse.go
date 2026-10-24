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
		FilterFactories:   chainDefault(),
		BuildVerdictFacts: buildSizeofMisuseVerdictFacts,
		Categories:        []string{"sizeof_pointer", "sizeof_pointer_ambig"},
		// `sizeof(p)` on a single-level pointer `T *p` is the pointer width where
		// the object size is intended (CWE-467) — but whether the object size WAS
		// intended is a context question the detector cannot prove (the redis scan
		// dismissed 11/11 of these auto-confirms). Both categories stay suspected
		// for the AI.
		CategoryConfidence: map[string]string{
			"sizeof_pointer":       "suspected",
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

func buildSizeofMisuseVerdictFacts(c Candidate) []VerdictFact {
	if c.VariableName == "" {
		return nil
	}
	return []VerdictFact{{
		Token:  "subject@" + c.VariableName,
		Detail: fmt.Sprintf("sizeof is applied to `%s` — the category states whether the result is a pointer width instead of the pointee size", c.VariableName),
	}}
}
