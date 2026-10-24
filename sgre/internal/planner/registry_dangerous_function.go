package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "dangerous-function",
		CWE:              "CWE-676",
		SeedEventType:    "DANGEROUS_FUNCTION",
		EvidenceType:     "DANGEROUS_FUNCTION",
		DefaultSuspicion: "confirmed",
		FilterChain:      "default",
		FilterFactories:  chainDefault(),
		// A call to a banned function is a POLICY finding — the function itself
		// is the defect, no context matters — so every category is confirmed
		// soundly (a name match, not a may-analysis). EXCEPTION: `assert_usage`
		// is handed to the AI, because whether an assert() guards caller input
		// (a defect) or an internal invariant (fine) needs intent.
		CategoryConfidence: map[string]string{
			"assert_usage":             "suspected",
			"obsolete_api_conditional": "suspected",
		},
		BuildVerdictFacts: buildDangerousFunctionVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "dangerous_function", Role: "sink", Detail: fmt.Sprintf("call to banned %s() (%s) at line %d in function %s", c.VariableName, c.Category, c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}

// buildDangerousFunctionVerdictFacts renders the decisive facts for a
// dangerous-function candidate: the policy rule name (banned-function /
// obsolete-api / assert-usage / ...), the replacement (when the rule carries
// one), and the call's expression. The AI classifies from these + the
// whole-function Code Context without opening the raw source.
//
// The policy@<category> token is the key signal: a banned-function /
// obsolete-api call is a POLICY violation (the function itself is the defect,
// no context matters), while assert_usage needs the AI to judge whether the
// assert guards caller input (a defect) or an internal invariant (fine).
func buildDangerousFunctionVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	if c.Category != "" {
		facts = append(facts, VerdictFact{
			Token:  "policy@" + c.Category,
			Detail: "policy rule: " + c.Category + " (banned_function / obsolete_api are POLICY violations — the function itself is the defect; assert_usage needs intent judgment)",
		})
	}
	if c.VariableName != "" {
		facts = append(facts, VerdictFact{
			Token:  "api@" + c.VariableName,
			Detail: "the banned/obsolete function being called",
		})
	}
	return facts
}
