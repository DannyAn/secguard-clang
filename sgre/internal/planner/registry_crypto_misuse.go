package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "crypto-misuse",
		CWE:               "CWE-327",
		LegacyCWEs:        []string{"CWE-326", "CWE-338"},
		SeedEventType:     "CRYPTO_MISUSE",
		EvidenceType:      "CRYPTO_MISUSE",
		DefaultSuspicion:  "suspected",
		FilterChain:       "default",
		BuildVerdictFacts: buildCryptoMisuseVerdictFacts,
		// weak_algorithm (DES/MD5/SHA1/RC4), weak_random (rand/srand) and
		// undersized_key are deterministic defects — the primitive itself is
		// provably broken regardless of call context, so the detector's verdict is
		// final and these are confirmed, not suspected. This matches the agent
		// prompt's "weak crypto is confirmed, period" rule (agent-body.md).
		CategoryConfidence: map[string]string{
			"weak_algorithm": "confirmed",
			"weak_random":    "confirmed",
			"undersized_key": "confirmed",
		},
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("crypto-misuse:%d:%s:%s", c.FileID, c.FunctionName, c.Category)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			detail := fmt.Sprintf("weak crypto in %s at line %d", c.FunctionName, c.Line)
			if c.CryptoReason != "" {
				detail = fmt.Sprintf("%s in %s at line %d", c.CryptoReason, c.FunctionName, c.Line)
			}
			frags := []EvidenceFragment{
				{Type: "crypto_misuse", Role: "sink", Detail: detail},
			}
			if c.CryptoKeySize > 0 {
				frags = append(frags, EvidenceFragment{Type: "key_size", Role: "condition", Detail: fmt.Sprintf("declared key size: %d bytes", c.CryptoKeySize)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}
