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
		FilterFactories:    chainDefault(),
		BuildVerdictFacts: buildCryptoMisuseVerdictFacts,
		// weak_algorithm (DES/MD5/SHA1/RC4), weak_random (rand/srand) and
		// undersized_key name a primitive that IS weak, but whether that is a
		// SECURITY defect depends on context (MD5 for a checksum is fine, MD5
		// for a password hash is broken). Hand every candidate to the AI, which
		// judges the use from the reason@ hint; the primitive weakness is not
		// itself proof of a defect.
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

func buildCryptoMisuseVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 2)
	if c.CryptoReason != "" {
		facts = append(facts, VerdictFact{
			Token:  "reason@" + c.CryptoReason,
			Detail: fmt.Sprintf("the detector's observed weakness at line %d: %s — the primitive itself is broken regardless of call context", c.Line, c.CryptoReason),
		})
	}
	if c.CryptoKeySize > 0 {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("key-size@%d", c.CryptoKeySize),
			Detail: fmt.Sprintf("the declared key size is %d bytes — under 16 bytes (128 bits) is below the modern-cipher minimum", c.CryptoKeySize),
		})
	}
	return facts
}
