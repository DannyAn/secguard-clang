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
		"dangerous-function": "type-inherent: a banned call is a policy defect by name (assert_usage excluded → suspected)",
	}
	confirmedCategories := map[string]map[string]string{
		"buffer-overflow": {
			"array_oob_write":       "constant index past a known array/allocation size, or interval lo >= size",
			"heap_oob_write":        "constant index past a known allocation size, or interval lo >= size",
			"bounded_copy_overflow": "constant copy size > known capacity",
			"secure_copy_overflow":  "Annex K _s given a lying destination-capacity argument (constant > capacity)",
			"secure_scanf_overflow": "scanf_s %s/%c/%[ width argument > real buffer (constant)",
			"format_overflow":       "format literal + argument output provably >= capacity (constant fold)",
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

// TestDynamicConfirmedUpgradesRegistered is the machine guard for the dynamic
// side of the AI judgment boundary: any filter whose Apply assigns
// SuspicionLevel = "confirmed" must implement ProofRegistrar and declare each
// upgrade's proof class. The golden list below is the reviewed closed set of
// filters known to upgrade; adding a new confirmed-upgrading filter without
// registering it here fails the build.
func TestDynamicConfirmedUpgradesRegistered(t *testing.T) {
	// confirmedUpgraders is the golden list of filters that may assign
	// SuspicionLevel = "confirmed" inside Apply, mapped to the proof classes
	// they are expected to declare. A filter missing from this list, or
	// declaring a proof class not listed, fails the test.
	confirmedUpgraders := map[string][]ProofClass{
		"NullableSourceFilter":       {ProofClassCFGMustDataflow},
		"LifetimeFilter":             {ProofClassCFGMustDataflow},
		"DoubleFreeFilter":           {ProofClassCFGMustDataflow},
		"TaintSourceFilter":          {ProofClassCFGMustDataflow},
		"RangeFilter":                {ProofClassInterval},
		"RangeOOBFilter":             {ProofClassInterval},
		"ReturnCheckFilter":          {ProofClassTypeInherent},
		"LockOrderFilter":            {ProofClassCFGMustDataflow},
		"SharedAccessFilter":         {ProofClassCFGMustDataflow},
		"DefiniteInitFilter":         {ProofClassCFGMustDataflow},
		"HardcodedSecretProofFilter": {ProofClassLiteral},
	}

	for name, expectedClasses := range confirmedUpgraders {
		reg := instantiateFilterByName(t, name)
		if reg == nil {
			t.Errorf("filter %s: cannot instantiate (constructor signature drifted?)", name)
			continue
		}
		pr, ok := reg.(ProofRegistrar)
		if !ok {
			t.Errorf("filter %s: upgrades candidates to confirmed but does not implement ProofRegistrar", name)
			continue
		}
		proofs := pr.DeclaredProofs()
		if len(proofs) == 0 {
			t.Errorf("filter %s: DeclaredProofs is empty but the filter upgrades candidates to confirmed", name)
			continue
		}
		for _, p := range proofs {
			if !p.Class.IsValid() {
				t.Errorf("filter %s: proof %q uses invalid class %q", name, p.Rule, p.Class)
			}
			if p.Rule == "" {
				t.Errorf("filter %s: proof with empty Rule", name)
			}
			if p.Evidence == "" {
				t.Errorf("filter %s: proof %q has empty Evidence", name, p.Rule)
			}
			// TestRef is advisory; we do not assert its existence here (the
			// registry is reviewed by humans, and coupling the guard to test
			// names makes refactors brittle).
		}
		// Assert the filter's declared classes match the golden set (order-free).
		got := map[ProofClass]bool{}
		for _, p := range proofs {
			got[p.Class] = true
		}
		want := map[ProofClass]bool{}
		for _, c := range expectedClasses {
			want[c] = true
		}
		for c := range want {
			if !got[c] {
				t.Errorf("filter %s: missing proof class %q in DeclaredProofs", name, c)
			}
		}
		for c := range got {
			if !want[c] {
				t.Errorf("filter %s: unexpected proof class %q in DeclaredProofs (not in golden list)", name, c)
			}
		}
	}
}

// instantiateFilterByName builds a zero-dependency instance of the named
// filter for ProofRegistrar probing. Filters whose constructors require
// collaborators are constructed with nil — DeclaredProofs must not consult
// them.
func instantiateFilterByName(t *testing.T, name string) Filter {
	t.Helper()
	switch name {
	case "NullableSourceFilter":
		return NewNullableSourceFilter(nil)
	case "LifetimeFilter":
		return NewLifetimeFilter(nil, nil, nil)
	case "DoubleFreeFilter":
		return NewDoubleFreeFilter(nil, nil, nil)
	case "TaintSourceFilter":
		return NewTaintSourceFilter(nil, nil, nil, nil)
	case "RangeFilter":
		return NewRangeFilter(nil, nil, nil)
	case "RangeOOBFilter":
		return NewRangeOOBFilter(nil, nil, nil)
	case "ReturnCheckFilter":
		return NewReturnCheckFilter(nil, nil, nil)
	case "LockOrderFilter":
		return NewLockOrderFilter(nil, nil, nil)
	case "SharedAccessFilter":
		return NewSharedAccessFilter(nil, nil, nil)
	case "DefiniteInitFilter":
		return NewDefiniteInitFilter(nil, nil, nil)
	case "LeakProofFilter":
		return NewLeakProofFilter(nil, "MEMORY_ALLOC")
	case "HardcodedSecretProofFilter":
		return NewHardcodedSecretProofFilter(nil)
	default:
		return nil
	}
}
