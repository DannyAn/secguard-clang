//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// TestNullDeref_OriginTiers pins the nullable-origin tier (Evidence Contract
// v2, B1): the tier a candidate lands in decides what the classifier must do,
// so a wrong tier is a protocol break, not a cosmetic issue. The caller-arg
// tier needs a mixed-source fixture and is covered at the buildHintParts /
// verdict-facts unit level (TestBuildHint + TestNullDerefVerdictFacts).
func TestNullDeref_OriginTiers(t *testing.T) {
	t.Run("cfg-proof", func(t *testing.T) {
		src := `void f(void) {
    int *p = NULL;
    p->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "f")
		if c.NullOriginTier != "cfg-proof" {
			t.Fatalf("explicit NULL reaching the deref: tier = %q, want cfg-proof", c.NullOriginTier)
		}
		if !strings.Contains(c.Hint, "null@cfg-proof") {
			t.Fatalf("hint %q must carry null@cfg-proof", c.Hint)
		}
	})

	t.Run("malloc-fail", func(t *testing.T) {
		src := `void f(void) {
    int *p = malloc(4);
    p->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "f")
		if c.NullOriginTier != "malloc-fail" {
			t.Fatalf("unchecked malloc result: tier = %q, want malloc-fail", c.NullOriginTier)
		}
		if !strings.Contains(c.Hint, "null@malloc-fail") {
			t.Fatalf("hint %q must carry null@malloc-fail", c.Hint)
		}
		if c.SuspicionLevel != "confirmed" {
			t.Fatalf("allocator source keeps the confirmed tier, got %q", c.SuspicionLevel)
		}
	})

	t.Run("external-unknown", func(t *testing.T) {
		src := `void f(void) {
    int *p = mylib_obtain();
    p->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "f")
		if c.NullOriginTier != "external-unknown" {
			t.Fatalf("unknown external call: tier = %q, want external-unknown", c.NullOriginTier)
		}
		if !strings.Contains(c.Hint, "null@external-unknown") {
			t.Fatalf("hint %q must carry null@external-unknown", c.Hint)
		}
		if c.SuspicionLevel != "suspected" {
			t.Fatalf("fail-open external stays suspected, got %q", c.SuspicionLevel)
		}
	})

	t.Run("verdict facts per tier", func(t *testing.T) {
		for _, tc := range []struct {
			tier  string
			token string
		}{
			{"cfg-proof", "null@cfg-proof"},
			{"malloc-fail", "null@malloc-fail"},
			{"caller-arg", "null@caller-arg"},
			{"external-unknown", "null@external-unknown"},
		} {
			facts := buildNullDerefVerdictFacts(Candidate{NullOriginTier: tc.tier, VariableName: "p", Line: 9})
			if len(facts) == 0 || facts[0].Token != tc.token {
				t.Fatalf("tier %s: first fact token = %v, want %s", tc.tier, facts, tc.token)
			}
		}
		facts := buildNullDerefVerdictFacts(Candidate{})
		if len(facts) != 1 || facts[0].Token != "guard@none" {
			t.Fatalf("tier-less candidate still carries the machine-verified guard fact, got %v", facts)
		}
	})

	// The Evidence Contract v2 F3 fix: a variable assigned the result of an
	// IN-SCAN callee the inter-procedural fixpoint proved nullable
	// (`cfg = get_shell_cfg(); cfg->field`) is malloc-fail — a proven-nullable
	// origin — not external-unknown. The callee body is embedded via
	// CalleeName → resolveCalleeDefs, so the hint carries callee@ and the AI
	// never opens the source.
	t.Run("in-scan nullable callee is malloc-fail", func(t *testing.T) {
		src := `typedef struct {
    unsigned int detect_time;
} shell_config_t;

typedef struct tag_space_s {
    shell_config_t *shell_conf;
} space_s;

static space_s g_space = {0};

shell_config_t *get_shell_cfg(void) {
    return g_space.shell_conf;
}

void set_detect_time(unsigned int time) {
    shell_config_t *shell_cfg = get_shell_cfg();
    shell_cfg->detect_time = time;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "set_detect_time")
		if c.NullOriginTier != "malloc-fail" {
			t.Fatalf("in-scan nullable callee: tier = %q, want malloc-fail", c.NullOriginTier)
		}
		if !strings.Contains(c.Hint, "null@malloc-fail") {
			t.Fatalf("hint %q must carry null@malloc-fail", c.Hint)
		}
		if !strings.Contains(c.Hint, "callee@nd.c:") {
			t.Fatalf("hint %q must carry callee@ (the get_shell_cfg body is embedded, no source read needed)", c.Hint)
		}
		if c.CalleeDefFile == "" {
			t.Fatalf("callee definition must be resolved for the embedded body")
		}
		for _, f := range c.VerdictFacts {
			if strings.HasPrefix(f.Token, "callee@") {
				return
			}
		}
		t.Fatalf("verdict facts %v must carry a callee@ fact", c.VerdictFacts)
	})

	// The fail-open side stays: a callee with NO definition in the scan is
	// genuinely external-unknown — the AI must verify it can return NULL.
	t.Run("external callee variable stays external-unknown", func(t *testing.T) {
		src := `typedef struct { int x; } cfg_t;

cfg_t *external_getter(void);

void use_external_var(void) {
    cfg_t *c = external_getter();
    c->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "use_external_var")
		if c.NullOriginTier != "external-unknown" {
			t.Fatalf("external callee via variable: tier = %q, want external-unknown", c.NullOriginTier)
		}
		if strings.Contains(c.Hint, "callee@") {
			t.Fatalf("hint %q must NOT carry callee@ for an out-of-scan callee", c.Hint)
		}
	})
}

// TestSynthCalleeAt pins the line-selection rule of the synthesized-callee
// lookup: the assignment closest before the dereference wins (matching the
// flow engine's kill semantics), and assignments after the dereference or on
// other variables never match.
func TestSynthCalleeAt(t *testing.T) {
	synth := []nullSource{
		{variable: "p", line: 10, origin: "first_nullable"},
		{variable: "p", line: 20, origin: "second_nullable"},
		{variable: "q", line: 15, origin: "other_var"},
	}
	if got := synthCalleeAt(synth, "p", 30); got != "second_nullable" {
		t.Fatalf("closest assignment before the deref: got %q, want second_nullable", got)
	}
	if got := synthCalleeAt(synth, "p", 15); got != "first_nullable" {
		t.Fatalf("only the first assignment reaches line 15: got %q, want first_nullable", got)
	}
	if got := synthCalleeAt(synth, "p", 10); got != "first_nullable" {
		t.Fatalf("assignment at the same line reaches: got %q, want first_nullable", got)
	}
	if got := synthCalleeAt(synth, "p", 9); got != "" {
		t.Fatalf("no assignment before line 9: got %q, want empty", got)
	}
	if got := synthCalleeAt(synth, "q", 30); got != "other_var" {
		t.Fatalf("other variable: got %q, want other_var", got)
	}
	if got := synthCalleeAt(nil, "p", 30); got != "" {
		t.Fatalf("nil sources: got %q, want empty", got)
	}
}

func firstNullCandidate(t *testing.T, res *PlanResult, fn string) EvidenceItem {
	t.Helper()
	for _, c := range res.Candidates {
		if c.Target.Function == fn {
			return c
		}
	}
	t.Fatalf("no null-deref candidate in function %s", fn)
	return EvidenceItem{}
}
