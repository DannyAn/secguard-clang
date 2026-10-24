package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:       "injection",
		CWE:        "CWE-78",
		LegacyCWEs: []string{"CWE-89"},
		CategoryCWEs: map[string]string{
			"command_injection":   "CWE-78",
			"sql_injection":       "CWE-89",
			"argument_injection":  "CWE-88",
			"xml_xpath_injection": "CWE-91",
			"xml_injection":       "CWE-91",
			"crlf_injection":      "CWE-93",
			"log_injection":       "CWE-117",
		},
		SeedEventType:    "INJECTION",
		EvidenceType:     "INJECTION",
		DefaultSuspicion: "suspected",
		FilterChain:      "injection",
		FilterFactories:    chainTaint(),
		ConvergeKey: func(c Candidate) string {
			// Key on (function, category, variable) so sprintf(source) +
			// sqlite3_exec(sink) sharing one buffer merge into one finding — the
			// same tainted variable is one root cause. Two sinks with DIFFERENT
			// categories (command_injection vs sql_injection) or different
			// variables stay distinct; two sinks with the SAME category and
			// variable deliberately collapse (same taint → same defect).
			return fmt.Sprintf("injection:%d:%s:%s:%s", c.FileID, c.FunctionName, c.Category, c.VariableName)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "unsafe_call", Role: "sink", Detail: fmt.Sprintf("unsafe function call %s in %s at line %d", c.APIName, c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: taintSourceDetail(c, "the sink")})
			}
			return frags
		},
	})
}
