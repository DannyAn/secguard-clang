package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:               "null-deref",
		CWE:                "CWE-476",
		SeedEventType:      "DEREFERENCE",
		EvidenceType:       "NULL_DEREFERENCE",
		DefaultSuspicion:   "confirmed",
		FilterChain:        "null-deref",
		ConvergeByVariable: true,
		BuildVerdictFacts:  buildNullDerefVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			fragments := make([]EvidenceFragment, 0, 4)
			if c.HasDefiniteNull {
				fragments = append(fragments, EvidenceFragment{
					Type:   "definite_null",
					Role:   "condition",
					Detail: fmt.Sprintf("variable %s is assigned NULL at line %d and dereferenced at line %d with no intervening reassignment (certain null-deref)", c.VariableName, c.SourceLine, c.Line),
				})
			} else if c.HasNullableSource {
				if c.CallerNullDetail != "" {
					fragments = append(fragments, EvidenceFragment{
						Type:   "caller_null",
						Role:   "source",
						Detail: fmt.Sprintf("parameter %s can be NULL: %s", c.VariableName, c.CallerNullDetail),
					})
				} else {
					fragments = append(fragments, EvidenceFragment{
						Type:   "nullable_source",
						Role:   "source",
						Detail: nullableSourceDetail(c),
					})
				}
			}
			if c.IsReachable {
				fragments = append(fragments, EvidenceFragment{
					Type:   "call_path",
					Role:   "path",
					Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName),
				})
			}
			if c.HasDataFlow {
				fragments = append(fragments, EvidenceFragment{
					Type:   "data_flow",
					Role:   "path",
					Detail: fmt.Sprintf("NULL value propagates to dereference at line %d", c.Line),
				})
			}
			// Every sink of the same nullable variable, not just the reported
			// line: the candidate is converged per variable, so a dereference
			// inside and after a branch are one root cause — but the fix must
			// cover all of them and the classifier must not read the single line
			// as the whole blast radius.
			if extra := otherDerefLines(c); len(extra) > 0 {
				fragments = append(fragments, EvidenceFragment{
					Type:   "dereference",
					Role:   "sink",
					Detail: fmt.Sprintf("the same nullable %s is also dereferenced at line(s) %s — one candidate covers every sink because every one of them reads the same null source", c.VariableName, joinLines(extra)),
				})
			}
			if len(fragments) == 0 {
				fragments = append(fragments, EvidenceFragment{
					Type:   "dereference",
					Role:   "sink",
					Detail: fmt.Sprintf("dereference of %s at line %d", c.VariableName, c.Line),
				})
			}
			return fragments
		},
		ReviewAssumptions: []string{
			"A dereference of a pointer that is provably NULL on some path is a real defect",
			"The pipeline tracks definite-null and nullable-source assignments",
		},
		RequiredEvidence: []string{"source of NULL value", "dereference location", "path from source to sink"},
		KnownLimitations: []string{
			"Macro context candidates are not auto-confirmed and excluded from review",
			"Pointer aliasing across function boundaries may not be fully tracked",
		},
	})
}
