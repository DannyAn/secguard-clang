package planner

import (
	"fmt"
	"strconv"
)

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "uninit",
		CWE:               "CWE-457",
		SeedEventType:     "VALUE_USE",
		EvidenceType:      "UNINIT_USE",
		DefaultSuspicion:  "suspected",
		FilterChain:       "uninit",
		FilterFactories:    chainUninit(),
		BuildVerdictFacts: buildUninitVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "uninit_use", Role: "sink", Detail: fmt.Sprintf("uninitialized variable '%s' used in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
			}
			if c.DeclLine > 0 {
				if c.Origin == "heap_uninit" {
					frags = append(frags, EvidenceFragment{Type: "allocation", Role: "source", Detail: fmt.Sprintf("variable '%s' allocated at line %d", c.VariableName, c.DeclLine)})
				} else {
					frags = append(frags, EvidenceFragment{Type: "declaration", Role: "source", Detail: fmt.Sprintf("variable '%s' declared at line %d", c.VariableName, c.DeclLine)})
				}
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"Use of an uninitialized variable is a real defect",
			"The pipeline tracks initialization state through the CFG",
		},
		RequiredEvidence: []string{"declaration without initialization", "use location", "path from declaration to use"},
		KnownLimitations: []string{
			"Heap/struct initialization via calloc/memset may not be fully recognized",
			"Cross-function initialization via output parameters may be missed",
		},
	})
}

func buildUninitVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	if c.SuspicionLevel == "confirmed" {
		facts = append(facts, VerdictFact{
			Token:  "certain-uninit",
			Detail: "three layers converged — the read is provably uninitialized; verify the statement matches and confirm",
		})
	} else if c.SuspicionLevel == "suspected" {
		facts = append(facts, VerdictFact{
			Token:  "maybe-uninit",
			Detail: "weaker tier — trace the write paths to the declaration",
		})
	}
	if c.Origin != "" {
		facts = append(facts, VerdictFact{
			Token:  "origin@" + c.Origin,
			Detail: fmt.Sprintf("the uninitialized storage is %s storage", c.Origin),
		})
	}
	if c.DeclLine > 0 {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("decl@%d", c.DeclLine),
			Detail: "the storage is declared here — the ## Code Context window covers it",
		})
	}
	if c.FieldPath != "" {
		facts = append(facts, VerdictFact{
			Token:  "field@" + compactHintValue(c.FieldPath),
			Detail: fmt.Sprintf("the uninitialized read target is `%s`, NOT the base pointer `%s` — judge whether that field/element is written before the read", c.FieldPath, c.VariableName),
		})
	}
	switch c.InitWrite {
	case "none":
		if c.Origin == "heap_uninit" || c.Origin == "struct_partial_uninit" {
			facts = append(facts, VerdictFact{
				Token:  "init@unseen",
				Detail: "no in-function write to the read target was found before the read, but heap/struct storage can be initialized by the allocating callee, memset, or an output parameter — verify the init path, do NOT confirm from this alone",
			})
		} else {
			facts = append(facts, VerdictFact{
				Token:  "init@none",
				Detail: "the detector proved the read target has NO write between the declaration/allocation and this read — the read is uninitialized by construction; confirm without tracing write paths",
			})
		}
	case "loop":
		if c.InitWriteLine > 0 {
			facts = append(facts, VerdictFact{
				Token:  fmt.Sprintf("init@%d", c.InitWriteLine),
				Detail: "the ONLY writes to the read target sit inside the loop body at line " + strconv.Itoa(c.InitWriteLine) + " — the loop condition may skip them on the first pass",
			})
			facts = append(facts, VerdictFact{
				Token:  "may-skip",
				Detail: "the initialization writes are loop-body-only: judge whether the loop condition can be false at entry (the Code Context window covers it); nothing else is in scope",
			})
		}
	}
	return facts
}
