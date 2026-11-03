package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "implicit-contract",
		CWE:               "CWE-20",
		SeedEventType:     "CONTRACT_GAP",
		EvidenceType:      "IMPLICIT_CONTRACT",
		DefaultSuspicion:  "suspected",
		FilterChain:       "implicit-contract",
		FilterFactories:   chainImplicitContract(),
		BuildVerdictFacts: buildImplicitContractVerdictFacts,
		Categories:        []string{"ptr_guard"},
		// One candidate per dereference site: a field null-checked on one path but
		// dereferenced on several others has one defect PER unguarded site, and the
		// guard-dominance filter drops only the guarded sites. Keying on use_line
		// keeps the unguarded sites distinct instead of collapsing them to the
		// first (possibly guarded) site.
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("implicit-contract:%d:%s:%s:%d", c.FileID, c.FunctionName, c.VariableName, c.UseLine)
		},
		// This type is the OPEN-WORLD half of the entry-validation gap: a
		// caller/framework-supplied struct field is dereferenced without a null
		// guard, and the code itself treats the field as nullable somewhere
		// (evidence "self"/"caller"). It is NEVER auto-confirmed — the field's
		// nullness is not statically provable, so the AI agent judges the caller
		// contract / business semantics. The provable (definite null source)
		// cases belong to null-deref (CWE-476); this type only fires where the
		// field is never written in-scope, so there is no double report.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "contract_gap", Role: "sink", Detail: fmt.Sprintf("pointer field %s (of parameter %s) is dereferenced at line %d with no dominating null guard", c.VariableName, c.Subject, c.UseLine)},
			}
			if c.CountField != "" {
				frags = append(frags, EvidenceFragment{Type: "count_field", Role: "condition", Detail: fmt.Sprintf("the use is gated by count/length field %s", c.CountField)})
			}
			frags = append(frags, EvidenceFragment{Type: "missing", Role: "condition", Detail: fmt.Sprintf("missing precondition: %s != NULL", c.VariableName)})
			switch c.EvidenceKind {
			case "self":
				frags = append(frags, EvidenceFragment{Type: "contract_evidence", Role: "source", Detail: fmt.Sprintf("function %s null-checks %s on another path, so it treats the field as nullable", c.FunctionName, c.VariableName)})
			case "sibling":
				detail := fmt.Sprintf("a SAME-FILE sibling function null-checks %s, so the same struct contract treats the field as nullable", c.VariableName)
				if c.SiblingGuardFunc != "" {
					detail = fmt.Sprintf("same-file sibling %s null-checks %s at line %d, so the same struct contract treats the field as nullable", c.SiblingGuardFunc, c.VariableName, c.SiblingGuardLine)
				}
				frags = append(frags, EvidenceFragment{Type: "contract_evidence", Role: "source", Detail: detail})
			case "sibling-weak":
				frags = append(frags, EvidenceFragment{Type: "contract_evidence", Role: "source", Detail: fmt.Sprintf("another FILE's function with the same parameter struct type null-checks %s — unrelated-TU, weak evidence", c.VariableName)})
			case "caller":
				frags = append(frags, EvidenceFragment{Type: "contract_evidence", Role: "source", Detail: fmt.Sprintf("a caller null-checks %s before the call, so the field is nullable at the call boundary", c.VariableName)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"A caller/framework-supplied struct field dereferenced without a guard may be NULL on the empty/unusual path",
			"The code null-checking the field elsewhere is evidence the field is nullable, not proof",
		},
		RequiredEvidence: []string{"dereference site", "count/length field gating the use", "same-file sibling null-guard evidence"},
		KnownLimitations: []string{
			"Field nullness is open-world: a framework may guarantee non-null, which only the AI can judge",
			"Only a SAME-FILE sibling guard is treated as proving evidence; self-only and cross-file type-anchored guards are pre-dismissed as non-proving (issue #200)",
		},
	})
}

func buildImplicitContractVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 3)
	if c.Subject != "" {
		facts = append(facts, VerdictFact{
			Token:  "subject@" + c.Subject,
			Detail: fmt.Sprintf("the contract is about parameter `%s`", c.Subject),
		})
	}
	if c.CountField != "" {
		facts = append(facts, VerdictFact{
			Token:  "count-field@" + c.CountField,
			Detail: fmt.Sprintf("`%s` gates the pointer use — the contract the function actually enforces", c.CountField),
		})
	}
	if c.EvidenceKind != "" {
		detail := fmt.Sprintf("the nullable treatment is proven in the %s — judge whether the missing precondition is a real contract gap", c.EvidenceKind)
		if c.EvidenceKind == "sibling" {
			detail = "a SAME-FILE sibling function with the same parameter struct type null-checks the same field — the same-TU comparison that makes this omission (rather than a design convention) the likely defect; judge whether the missing guard can actually see NULL"
		}
		facts = append(facts, VerdictFact{Token: "evidence-kind@" + c.EvidenceKind, Detail: detail})
	}
	if c.SiblingGuardFunc != "" {
		token := "sibling-guard@" + c.SiblingGuardFunc
		detail := fmt.Sprintf("the same-file sibling `%s` null-checks the same field here", c.SiblingGuardFunc)
		if c.SiblingGuardLine > 0 {
			token = fmt.Sprintf("sibling-guard@%s:%d", c.SiblingGuardFunc, c.SiblingGuardLine)
		}
		facts = append(facts, VerdictFact{Token: token, Detail: detail})
	}
	return facts
}
