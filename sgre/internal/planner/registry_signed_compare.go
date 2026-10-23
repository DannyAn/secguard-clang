package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "signed-compare",
		CWE:              "CWE-681",
		SeedEventType:    "SIGNED_COMPARE",
		EvidenceType:     "SIGNED_COMPARE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		Categories:       []string{"signed_compare"},
		// The detector only emits when the compared variable's declared type is
		// provably unsigned (an `unsigned`/`size_t`/`uint*_t` spelling), and an
		// unsigned value is never `< 0` — the dead comparison is a confirmed
		// CWE-681 defect. The suspected default is a backstop, never reached in
		// practice.
		CategoryConfidence: map[string]string{
			"signed_compare": "confirmed",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "signed_compare", Role: "sink", Detail: fmt.Sprintf("unsigned value compared with zero/negative at line %d in function %s", c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}
