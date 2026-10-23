package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "hardcoded-secret",
		CWE:               "CWE-798",
		SeedEventType:     "HARDCODED_SECRET",
		EvidenceType:      "HARDCODED_SECRET",
		DefaultSuspicion:  "suspected",
		FilterChain:       "hardcoded-secret",
		BuildVerdictFacts: buildHardcodedSecretVerdictFacts,
		// A literal whose VALUE is secret-shaped (a known token prefix, high
		// Shannon entropy, URL-embedded credentials) is proven, so the
		// HardcodedSecretProofFilter auto-confirms it. A match on the
		// variable/field name ALONE may be a placeholder (`"REPLACE_ME"`) or a
		// test credential (`test_password = "test123"`), so it stays suspected
		// and the AI judges it, instead of the pipeline emitting a confirmed
		// false positive the skill's rules can never reach.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "hardcoded_secret", Role: "sink", Detail: fmt.Sprintf("hardcoded secret candidate in %s at line %d", c.FunctionName, c.Line)},
				{Type: "match_kind", Role: "condition", Detail: "name-only match: the variable/field name is secret-bearing but the value is low-entropy — judge whether it is a real credential, a placeholder, or a test value (value-proven secrets are auto-confirmed and never reach this stage)"},
			}
			if c.SecretValue != "" {
				frags = append(frags, EvidenceFragment{
					Type:   "secret_value",
					Role:   "source",
					Detail: fmt.Sprintf("literal value: %s — judge from the prefix and length whether it is a placeholder (REPLACE…), a test value (test…), or a real weak credential; the full literal is withheld from the evidence file", maskSecret(c.SecretValue)),
				})
			}
			return frags
		},
	})
}
