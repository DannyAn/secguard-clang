package planner

import (
	"fmt"
	"path/filepath"
)

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:               "null-deref",
		CWE:                "CWE-476",
		SeedEventType:      "DEREFERENCE",
		EvidenceType:       "NULL_DEREFERENCE",
		DefaultSuspicion:   "confirmed",
		FilterChain:        "null-deref",
		FilterFactories:    chainNullDeref(),
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

func buildNullDerefVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	switch c.NullOriginTier {
	case "cfg-proof":
		detail := fmt.Sprintf("the CFG proves a NULL assignment to %s reaches the dereference at line %d on every path — machine-proved CWE-476", c.VariableName, c.Line)
		if c.MacroContext {
			// The CFG does not expand function-like macros, so the "no
			// intervening reassignment" premise is unverified here: an
			// iteration macro assigns its iterator in the loop header. Keep the
			// fact (the null assignment is real) but never tell the classifier
			// to confirm without checking the macro.
			detail = fmt.Sprintf("the CFG finds a NULL assignment to %s with no in-function reassignment before the dereference at line %d, BUT a function-like macro is in scope and CFG analysis does not expand macros — verify the macro does not assign %s (a list-iteration macro like SLL_Scan/list_for_each_* assigns its iterator in the loop header, which makes this proof FALSE) before confirming", c.VariableName, c.Line, c.VariableName)
		}
		facts = append(facts, VerdictFact{
			Token:  "null@cfg-proof",
			Detail: detail,
		})
	case "malloc-fail":
		name := c.NullableOriginName
		if name == "" {
			name = "a nullable callee"
		}
		facts = append(facts, VerdictFact{
			Token:  "null@malloc-fail",
			Detail: fmt.Sprintf("the null source is `%s`%s — a MAY-null call result (allocator / known maybe-null libc / return-NULL callee); judge whether it can actually return NULL here and whether the deref is guarded, then confirm or dismiss", name, derivedSuffix(c)),
		})
	case "assumed-return":
		name := c.NullableOriginName
		if name == "" {
			name = "the callee"
		}
		facts = append(facts, VerdictFact{
			Token:  "null@assumed-return",
			Detail: fmt.Sprintf("`%s` was graded maybe-null only by fail-open assumption (it returns a parameter, a field, or an unknown call) — the body is embedded below, judge whether that value can actually be NULL", name),
		})
	case "caller-arg":
		detail := c.CallerNullDetail
		if detail == "" {
			detail = "an inter-procedural caller passes the value unproven non-null"
		}
		if c.DerivedFrom != "" {
			facts = append(facts, VerdictFact{
				Token:  "null@caller-arg",
				Detail: fmt.Sprintf("`%s` is a copy/cast of parameter `%s`: %s — judge whether that caller can pass NULL", c.VariableName, c.DerivedFrom, detail),
			})
		} else {
			facts = append(facts, VerdictFact{
				Token:  "null@caller-arg",
				Detail: fmt.Sprintf("the null source is parameter `%s`: %s — judge whether that caller can pass NULL", c.VariableName, detail),
			})
		}
	case "opaque-origin":
		facts = append(facts, VerdictFact{
			Token:  "null@opaque-origin",
			Detail: fmt.Sprintf("the null source of `%s`%s is a value the scan tree cannot see (an external caller's argument, a field value whose definition is out of tree, or an open-world value read through an opaque field/dereference) — the pipeline only ASSUMES it may be NULL; judge whether that source can actually yield NULL", c.VariableName, derivedSuffix(c)),
		})
	case "external-unknown":
		facts = append(facts, VerdictFact{
			Token:  "null@external-unknown",
			Detail: "the ONLY null source is an unproven external call — an analyzer fail-open assumption, NOT evidence: verify the callee can return NULL, otherwise dismiss",
		})
	}
	if c.CalleeNullCondition != "" {
		facts = append(facts, VerdictFact{
			Token:  "retnull-cond@" + c.CalleeNullCondition,
			Detail: fmt.Sprintf("the callee returns NULL only when `%s` holds (its body is under ## Callee Definition) — a call inside the branch that EXCLUDES this condition cannot yield NULL; compare it with the enclosing branch in the Code Context", c.CalleeNullCondition),
		})
	}
	if c.SourceLine > 0 && c.NullOriginTier != "cfg-proof" {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("src@%d", c.SourceLine),
			Detail: "the nullable origin is assigned here — the ## Code Context window covers it",
		})
	}
	if (c.IsCallResultDeref || c.CalleeName != "") && c.CalleeDefFile != "" {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("callee@%s:%d", filepath.Base(c.CalleeDefFile), c.CalleeDefLine),
			Detail: "the callee's definition in this scan; its body is embedded under ## Callee Definition — judge the return-nullability from the body, no source read needed",
		})
	}
	// cfg-proof already entails "no guard" (the CFG proved NULL reaches on
	// every path), so restating it is redundant noise. For the fail-open
	// tiers the fact is real but bounded: the pipeline only proved it found
	// no DOMINATING same-function guard — caller-side and cross-function
	// guards may still exist, and the tier judgment is where they belong.
	if c.NullOriginTier != "cfg-proof" {
		facts = append(facts, VerdictFact{
			Token:  "guard@none",
			Detail: "the pipeline found no dominating same-function null guard before the dereference (short-circuit and ternary shapes were filtered); caller-side or cross-function guards may still exist — judge them when judging the tier",
		})
	}
	return facts
}
