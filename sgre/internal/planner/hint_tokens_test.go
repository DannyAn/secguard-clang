package planner

import (
	"strings"
	"testing"
)

// TestHintTokenRegistryWellFormed pins the registry invariants every consumer
// relies on: keys are unique, value-bearing keys end in "@", bare keys do
// not, and every spec carries a real description (the legend is generated
// from these — an empty description would render a dead legend line).
func TestHintTokenRegistryWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range hintTokenRegistry {
		if spec.Key == "" {
			t.Fatalf("registry entry with empty Key: %+v", spec)
		}
		if seen[spec.Key] {
			t.Fatalf("duplicate registry key %q", spec.Key)
		}
		seen[spec.Key] = true
		if strings.HasSuffix(spec.Key, "@") {
			if len(spec.Key) < 2 {
				t.Fatalf("value-bearing key %q has no prefix before @", spec.Key)
			}
		} else if strings.Contains(spec.Key, "@") {
			// Enumerated exact token (contract@known, guard@none): the value
			// is a fixed enum member with its own semantics. Its prefix must
			// not ALSO be a registered prefix key, or the two descriptions
			// would fight over the same emission form.
			prefix := spec.Key[:strings.Index(spec.Key, "@")+1]
			for _, other := range hintTokenRegistry {
				if other.Key == prefix {
					t.Fatalf("enumerated key %q conflicts with registered prefix key %q", spec.Key, prefix)
				}
			}
		}
		if strings.TrimSpace(spec.Description) == "" {
			t.Fatalf("registry key %q has an empty description — the generated legend would be a dead line", spec.Key)
		}
		if strings.Contains(spec.Display, "{value}") {
			t.Fatalf("registry key %q: Display must be the final legend form, not a template", spec.Key)
		}
	}
}

// TestBuildHintPartsTokensRegistered is the completeness half of the guard:
// every token buildHintParts can emit must resolve against the registry, so
// the "## Pipeline Tokens" rendering always annotates and the generated
// legend never lies by omission. The cases cover every emission branch in
// buildHintParts (type-specific switches plus the shared tail).
func TestBuildHintPartsTokensRegistered(t *testing.T) {
	cases := []struct {
		name     string
		vulnType string
		c        Candidate
	}{
		{"shared flags", "null-deref", Candidate{SourceLine: 12, HasNullableSource: true, HasTaintSource: true, GuardStrength: "weak", MacroContext: true, APIName: "malloc", Category: "x"}},
		{"definite null", "null-deref", Candidate{HasDefiniteNull: true}},
		{"contract known + callee", "unchecked-return", Candidate{ContractKnown: true, CalleeDefFile: "pool.c", CalleeDefLine: 37}},
		{"contract unknown", "unchecked-return", Candidate{}},
		{"divisor shapes", "divide-by-zero", Candidate{VariableName: "n"}},
		{"uninit tiers", "uninit", Candidate{SuspicionLevel: "confirmed"}},
		{"uninit maybe", "uninit", Candidate{SuspicionLevel: "suspected"}},
		{"unsigned sub provenance", "integer-overflow", Candidate{Category: "unsigned_sub_underflow", LHSKind: "param", RHSKind: "local", SubRHSInfluenced: true, SubLHSInfluenced: true, SubSink: "call_arg"}},
		{"deadlock pair", "deadlock", Candidate{MutexA: "m1", MutexB: "m2", ReverseFunc: "other"}},
		{"uaf free", "use-after-free", Candidate{FreeLine: 9}},
		{"double free", "double-free", Candidate{FirstFree: 10, SecondFree: 20, MayFree: true}},
		{"shared data race", "race-condition", Candidate{Category: "shared_data_race", ThreadFunctions: "a,b", ThreadInstances: 2, WriteLine: 15}},
		{"toctou shared state", "race-condition", Candidate{Category: "toctou_shared_state", Mutex: "g_lock", LockLine: 3, UnlockLine: 7}},
		{"toctou pair", "race-condition", Candidate{Category: "toctou", CheckFunction: "access", UseFunction: "fopen", CheckPathArg: "path"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := GetVulnTypeSpec(tc.vulnType)
			if err != nil {
				t.Fatalf("spec: %v", err)
			}
			parts := buildHintParts(tc.c, spec)
			if len(parts) == 0 {
				t.Fatalf("case %s produced no tokens — extend the fixture to exercise its emission branch", tc.name)
			}
			for _, tok := range parts {
				if _, _, ok := matchHintToken(tok); !ok {
					t.Errorf("emitted token %q is NOT in hintTokenRegistry — register it in hint_tokens.go or stop emitting it", tok)
				}
				if strings.Contains(tok, " ") {
					t.Errorf("emitted token %q contains a space (tokens must stay single tokens)", tok)
				}
			}
		})
	}
}

// TestDescribeHintTokenRendersValue pins the {value} substitution so the
// per-candidate annotation names the actual line/function instead of the
// template placeholder.
func TestDescribeHintTokenRendersValue(t *testing.T) {
	got := DescribeHintToken("src@44")
	if !strings.Contains(got, "`src@44`") || !strings.Contains(got, "line 44") {
		t.Errorf("DescribeHintToken(src@44) = %q, want the token echoed with the value substituted", got)
	}
	got = DescribeHintToken("maybe-null")
	if !strings.Contains(got, "`maybe-null`") || !strings.Contains(got, "NOT a proof") {
		t.Errorf("DescribeHintToken(maybe-null) = %q, want the bare token echoed with its description", got)
	}
	got = DescribeHintToken("totally-unknown-token")
	if !strings.Contains(got, "`totally-unknown-token`") {
		t.Errorf("DescribeHintToken(unknown) = %q, want the token echoed unannotated", got)
	}
}

// TestHintLegendLinesSubstituted pins that the legend never leaks the
// {value} placeholder: legend lines show the Display form (<value> where a
// value belongs), not raw templates.
func TestHintLegendLinesSubstituted(t *testing.T) {
	lines := HintLegendLines()
	if len(lines) != len(hintTokenRegistry) {
		t.Fatalf("HintLegendLines returned %d lines for %d registry entries", len(lines), len(hintTokenRegistry))
	}
	for _, line := range lines {
		if strings.Contains(line, "{value}") {
			t.Errorf("legend line leaks the {{value}} template: %q", line)
		}
		if !strings.Contains(line, "`") {
			t.Errorf("legend line has no backquoted token: %q", line)
		}
	}
}
