package planner

import (
	"sort"
	"testing"
)

// TestConfirmedTierPolicy is the machine guard for the AI judgment boundary
// (see AI_JUDGMENT_BOUNDARY.md). It locks two facts:
//
//  1. The suspicion vocabulary is exactly the three tiers confirmed > suspected
//     > possible (the ranker already orders them; here we assert the registry
//     uses no other token).
//  2. The static "confirmed" set — every category the registry marks confirmed
//     (CategoryConfidence == "confirmed") and every type defaulting to confirmed
//     — is a CLOSED, reviewed list. A new auto-confirmed category/type without a
//     documented proof class fails this test, forcing the author to register it
//     here and in AI_JUDGMENT_BOUNDARY.md rather than silently widening the
//     deterministic tier onto a heuristic.
func TestConfirmedTierPolicy(t *testing.T) {
	validTiers := map[string]bool{"confirmed": true, "suspected": true, "possible": true}

	// Golden lists — the reviewed deterministic tier (v0.8.0).
	defaultConfirmed := map[string]string{
		"null-deref":         "flow filter upgrades to confirmed only on must-null (has_definite_null)",
		"signal-handler":     "type-inherent: POSIX async-signal-safe list is fixed and authoritative",
		"dangerous-function": "type-inherent: a banned/obsolete libc call is a policy defect by name",
	}
	confirmedCategories := map[string]map[string]string{
		"buffer-overflow": {
			"array_oob_write":        "constant index past a known array/allocation size, or interval lo >= size",
			"heap_oob_write":         "constant index past a known allocation size, or interval lo >= size",
			"bounded_copy_overflow":  "constant copy size > known capacity",
			"secure_copy_overflow":   "Annex K _s given a lying destination-capacity argument (constant > capacity)",
			"secure_scanf_overflow":  "scanf_s %s/%c/%[ width argument > real buffer (constant)",
			"format_overflow":        "format literal + argument output provably >= capacity (constant fold)",
		},
		"integer-overflow": {
			"definite_overflow": "literal-constant arithmetic provably overflows the type (constant fold)",
		},
		"out-of-bounds": {
			"array_oob_read": "constant index past a known array size (read)",
			"heap_oob_read":  "constant index past a known allocation size (read)",
		},
		"crypto-misuse": {
			"weak_algorithm": "literal: DES/3DES/MD5/SHA-1/RC4/rand() are weak by CWE-327 definition",
			"weak_random":    "literal: rand()/srand() are weak PRNGs by CWE-338 definition",
			"undersized_key": "literal: key size below the algorithm's minimum",
		},
		"sizeof-misuse": {
			"sizeof_pointer": "literal: sizeof(pointer) vs sizeof(pointee) is always wrong",
		},
		"signed-compare": {
			"signed_compare": "literal: signed/unsigned comparison with a provable sign",
		},
	}

	// Enumerate the live registry.
	gotDefault := map[string]bool{}
	gotCategories := map[string][]string{}
	for _, name := range AllVulnTypes() {
		spec, err := GetVulnTypeSpec(name)
		if err != nil {
			t.Fatalf("GetVulnTypeSpec(%q): %v", name, err)
		}
		if spec.DefaultSuspicion != "" {
			if !validTiers[spec.DefaultSuspicion] {
				t.Errorf("type %s: DefaultSuspicion %q is not one of confirmed/suspected/possible", name, spec.DefaultSuspicion)
			}
			if spec.DefaultSuspicion == "confirmed" {
				gotDefault[name] = true
			}
		}
		for cat, lvl := range spec.CategoryConfidence {
			if !validTiers[lvl] {
				t.Errorf("type %s category %s: suspicion %q is not one of confirmed/suspected/possible", name, cat, lvl)
			}
			if lvl == "confirmed" {
				gotCategories[name] = append(gotCategories[name], cat)
			}
		}
	}

	// 1. Default-confirmed types must match the golden set exactly.
	for name := range gotDefault {
		if _, ok := defaultConfirmed[name]; !ok {
			t.Errorf("type %s defaults to confirmed but is NOT in the reviewed golden list — register its proof class in AI_JUDGMENT_BOUNDARY.md and this test", name)
		}
	}
	for name := range defaultConfirmed {
		if !gotDefault[name] {
			t.Errorf("type %s is in the golden confirmed list but no longer defaults to confirmed — update the golden list", name)
		}
	}

	// 2. Confirmed categories must match the golden set exactly.
	for name, cats := range gotCategories {
		sort.Strings(cats)
		gold, ok := confirmedCategories[name]
		if !ok {
			t.Errorf("type %s has confirmed categories %v but no golden entry — register each proof class", name, cats)
			continue
		}
		goldSorted := make([]string, 0, len(gold))
		for c := range gold {
			goldSorted = append(goldSorted, c)
		}
		sort.Strings(goldSorted)
		if !equalStrings(cats, goldSorted) {
			t.Errorf("type %s confirmed categories drifted: got %v, golden %v", name, cats, goldSorted)
		}
	}
	for name, gold := range confirmedCategories {
		if len(gotCategories[name]) == 0 {
			t.Errorf("type %s has golden confirmed categories %v but none are confirmed anymore — update the golden list", name, mapKeys(gold))
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
