package planner

import (
	"strings"
	"testing"
)

// TestBuildHintNeverEmpty is the R2-08 invariant: for every type whose
// decisive fact the pipeline has already computed, the _index.md Hint column
// must carry it, so a subagent never has to open evidence files just to learn
// what a candidate is. Each case gives the type its signature candidate
// fields and asserts the hint is not the "—" placeholder and names the
// decisive token.
func TestBuildHintNeverEmpty(t *testing.T) {
	cases := []struct {
		name     string
		vulnType string
		c        Candidate
		contains string
	}{
		{"deadlock lock pair", "deadlock", Candidate{MutexA: "mutex_a", MutexB: "mutex_b"}, "locks@mutex_a|mutex_b"},
		{"deadlock reverse func", "deadlock", Candidate{MutexA: "a", MutexB: "b", ReverseFunc: "other_fn"}, "reverse@other_fn"},
		{"use-after-free free line", "use-after-free", Candidate{FreeLine: 42}, "free@42"},
		{"double-free free lines", "double-free", Candidate{FirstFree: 10, SecondFree: 20}, "free@10,20"},
		{"memory-leak acquire api", "memory-leak", Candidate{APIName: "malloc"}, "api@malloc"},
		{"resource-leak acquire api", "resource-leak", Candidate{APIName: "fopen"}, "api@fopen"},
		{"unchecked-return unknown contract", "unchecked-return", Candidate{}, "contract@unknown"},
		{"uninit confirmed tier", "uninit", Candidate{SuspicionLevel: "confirmed"}, "certain-uninit"},
		{"integer-overflow lhs influenced", "integer-overflow", Candidate{Category: "unsigned_sub_underflow", LHSKind: "param", SubLHSInfluenced: true}, "lhs-influenced"},
		{"crypto category", "crypto-misuse", Candidate{Category: "weak_algorithm"}, "cat@weak_algorithm"},
		{"format-string api", "format-string", Candidate{APIName: "printf"}, "api@printf"},
		{"race shared data race threads", "race-condition", Candidate{Category: "shared_data_race", ThreadFunctions: "thread_race"}, "threads@thread_race"},
		{"race shared data race write", "race-condition", Candidate{Category: "shared_data_race", WriteLine: 15}, "write@15"},
		{"race toctou shared state lock range", "race-condition", Candidate{Category: "toctou_shared_state", Mutex: "g_mutex", LockLine: 42, UnlockLine: 44}, "lock@42-44"},
		{"race toctou check/use pair", "race-condition", Candidate{Category: "toctou", CheckFunction: "access", UseFunction: "fopen", CheckPathArg: "path"}, "check@access→use@fopen"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := GetVulnTypeSpec(tc.vulnType)
			if err != nil {
				t.Fatalf("spec: %v", err)
			}
			hint := buildHint(tc.c, spec)
			if hint == "—" {
				t.Fatalf("hint is the empty placeholder for %s — the type's decisive fact must reach the _index row", tc.vulnType)
			}
			if !strings.Contains(hint, tc.contains) {
				t.Errorf("hint %q does not carry %q", hint, tc.contains)
			}
		})
	}
}
