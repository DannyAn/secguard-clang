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
		if c.SuspicionLevel != "suspected" {
			t.Fatalf("allocator source is may-null, not must-null: suspected, got %q", c.SuspicionLevel)
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
			{"assumed-return", "null@assumed-return"},
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

	// The Evidence Contract v2 F3 fix, proven half: a variable assigned the
	// result of an IN-SCAN callee the inter-procedural fixpoint graded
	// PROVEN (a concrete NULL witness: a literal return NULL path) keeps the
	// textbook malloc-fail tier, but a literal return NULL is a may-null
	// witness, not a must-null proof — suspected for the AI. The callee body
	// is embedded via CalleeName → resolveCalleeDefs, so the hint carries
	// callee@ and the AI judges the embedded body.
	t.Run("in-scan proven callee is malloc-fail", func(t *testing.T) {
		src := `typedef struct { int x; } cfg_t;

static cfg_t g_cfg;

cfg_t *find_opt(void) {
    if (g_cfg.x == 0) {
        return NULL;
    }
    return &g_cfg;
}

void use_opt(void) {
    cfg_t *opt = find_opt();
    opt->x = 1;
}
`
		c := firstNullCandidate(t, planNullDerefSrc(t, src), "use_opt")
		if c.NullOriginTier != "malloc-fail" {
			t.Fatalf("in-scan proven callee: tier = %q, want malloc-fail", c.NullOriginTier)
		}
		if c.SuspicionLevel != "suspected" {
			t.Fatalf("a proven-nullable callee (literal return NULL) is may-null, got %q", c.SuspicionLevel)
		}
		if !strings.Contains(c.Hint, "null@malloc-fail") {
			t.Fatalf("hint %q must carry null@malloc-fail", c.Hint)
		}
		if !strings.Contains(c.Hint, "callee@nd.c:") {
			t.Fatalf("hint %q must carry callee@ (the find_opt body is embedded, no source read needed)", c.Hint)
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

	// The Evidence Contract v2 F3 fix, assumed half: an IN-SCAN callee graded
	// only by FAIL-OPEN (it returns a zero-initialized struct field) is
	// labelled assumed-return and stays suspected — the AI judges the
	// assumption from the embedded body instead of rubber-stamping a
	// "proven" prior.
	t.Run("in-scan fail-open callee is assumed-return", func(t *testing.T) {
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
		if c.NullOriginTier != "assumed-return" {
			t.Fatalf("in-scan fail-open callee: tier = %q, want assumed-return", c.NullOriginTier)
		}
		if c.SuspicionLevel != "suspected" {
			t.Fatalf("a fail-open callee stays suspected, got %q", c.SuspicionLevel)
		}
		if !strings.Contains(c.Hint, "null@assumed-return") {
			t.Fatalf("hint %q must carry null@assumed-return", c.Hint)
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

// TestNullDeref_DerivedOriginTier pins the tier of a DERIVED pointer: when the
// candidate's variable is only a value-preserving copy/cast of another variable
// (`q = (T *)param`, `q = t` where t is the opaque field read), the nullable
// origin belongs to that variable. Before this, every such candidate fell
// through to external-unknown, whose detail claims "the ONLY null source is an
// unproven external CALL" — false when there is no callee at all, and enough to
// make the classifier dismiss a real caller-argument / opaque-field source.
func TestNullDeref_DerivedOriginTier(t *testing.T) {
	src := `typedef struct { int x; } T_t;

T_t *ext_obtain(void);

int derived_cast(Opaque_t *dc_src)
{
    T_t *dc_q = (T_t *)dc_src;
    return dc_q->x;
}

int derived_field(Opaque_t *df_m)
{
    T_t *df_t = (T_t *)(df_m->data);
    T_t *df_q = df_t;
    return df_q->x;
}

int derived_malloc(void)
{
    T_t *dm_p = (T_t *)malloc(sizeof(T_t));
    T_t *dm_q = dm_p;
    return dm_q->x;
}

int derived_chain(Opaque_t *dh_z)
{
    T_t *dh_a = (T_t *)dh_z;
    T_t *dh_b = (T_t *)dh_a;
    return dh_b->x;
}

int derived_external(void)
{
    T_t *de_p = ext_obtain();
    T_t *de_q = de_p;
    return de_q->x;
}
`
	// runOpaqueNullPlan also runs the caller_null / opaque_null detectors, which
	// are what seed the parameter- and opaque-field-derived sources this test is
	// about (planNullDerefSrc covers literal / external-call sources only).
	res := runOpaqueNullPlan(t, map[string]string{"nd.c": src})
	candidateFor := func(fn, variable string) EvidenceItem {
		t.Helper()
		for _, c := range res.Candidates {
			if c.Target.Function == fn && c.Target.Variable == variable {
				return c
			}
		}
		t.Fatalf("no null-deref candidate for %s/%s; got %+v", fn, variable, res.Candidates)
		return EvidenceItem{}
	}

	// A cast of a pointer parameter: the origin is the caller argument, and the
	// verdict sentence must name the parameter, not the derived local.
	cast := candidateFor("derived_cast", "dc_q")
	if cast.NullOriginTier != "caller-arg" {
		t.Fatalf("derived_cast dc_q: tier = %q, want caller-arg", cast.NullOriginTier)
	}
	if cast.DerivedFrom != "dc_src" {
		t.Fatalf("derived_cast dc_q: derived_from = %q, want dc_src", cast.DerivedFrom)
	}
	if !strings.Contains(cast.Hint, "null@caller-arg") || !strings.Contains(cast.Hint, "caller-null@") {
		t.Fatalf("derived_cast dc_q: hint = %q, want null@caller-arg + caller-null@ witness", cast.Hint)
	}
	for _, f := range cast.VerdictFacts {
		if f.Token != "null@caller-arg" {
			continue
		}
		if !strings.Contains(f.Detail, "copy/cast of parameter `dc_src`") {
			t.Fatalf("verdict fact must attribute the origin parameter, got %q", f.Detail)
		}
	}

	// A copy of the opaque field-read value keeps the opaque-origin tier.
	field := candidateFor("derived_field", "df_q")
	if field.NullOriginTier != "opaque-origin" {
		t.Fatalf("derived_field df_q: tier = %q, want opaque-origin", field.NullOriginTier)
	}
	if field.DerivedFrom != "df_t" {
		t.Fatalf("derived_field df_q: derived_from = %q, want df_t", field.DerivedFrom)
	}

	// A copy of an allocator result is the proven-nullable tier, naming the
	// allocator. It stays suspected: widening the auto-confirm tier is a
	// boundary change, not part of a tier-label fix.
	alloc := candidateFor("derived_malloc", "dm_q")
	if alloc.NullOriginTier != "malloc-fail" {
		t.Fatalf("derived_malloc dm_q: tier = %q, want malloc-fail", alloc.NullOriginTier)
	}
	if alloc.DerivedFrom != "dm_p" {
		t.Fatalf("derived_malloc dm_q: derived_from = %q, want dm_p", alloc.DerivedFrom)
	}
	var allocFact string
	for _, f := range alloc.VerdictFacts {
		if f.Token == "null@malloc-fail" {
			allocFact = f.Detail
		}
	}
	if !strings.Contains(allocFact, "`malloc`") || !strings.Contains(allocFact, "reached through `dm_p`") {
		t.Fatalf("malloc-fail verdict fact must name the allocator and the origin variable, got %q", allocFact)
	}
	if alloc.SuspicionLevel != "suspected" {
		t.Fatalf("a DERIVED allocator copy must not auto-confirm in this round, got %q", alloc.SuspicionLevel)
	}

	// Chained casts resolve to the parameter root, not the intermediate hop.
	chain := candidateFor("derived_chain", "dh_b")
	if chain.NullOriginTier != "caller-arg" || chain.DerivedFrom != "dh_z" {
		t.Fatalf("derived_chain dh_b: tier/from = %q/%q, want caller-arg/dh_z", chain.NullOriginTier, chain.DerivedFrom)
	}

	// A copy of an unknown external call stays external-unknown (the tier is
	// correct there), but still names the variable that owns the source.
	ext := candidateFor("derived_external", "de_q")
	if ext.NullOriginTier != "external-unknown" {
		t.Fatalf("derived_external de_q: tier = %q, want external-unknown", ext.NullOriginTier)
	}
	if ext.DerivedFrom != "de_p" {
		t.Fatalf("derived_external de_q: derived_from = %q, want de_p", ext.DerivedFrom)
	}
}

// The field_read / deref_read origins introduced for `p = p->next` (ND-02) and
// `r = *(T **)msg` (NP-04) are values the scan tree cannot see — a field value /
// a pointed-to value whose content is open-world — so they belong to the
// opaque-origin tier, NOT external-unknown. Falling through to external-unknown
// made the verdict fact claim "the only null source is an unproven external
// CALL", which is false and misdirects the classifier.
func TestNullDerefOriginTiers_FieldReadAndDerefRead(t *testing.T) {
	src := `typedef struct node { int x; int y; struct node *next; } node_t;
extern node_t *get_node(void);

void traverse(void) {
    node_t *p = get_node();
    while (p != NULL) {
        p = p->next;
        p->y = 2;
    }
}

void deref_read_case(void *msg) {
    int *r = *(int **)msg;
    *r = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	byFn := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFn[c.Target.Function] = c
	}
	if c, ok := byFn["traverse"]; ok {
		if c.NullOriginTier != "opaque-origin" {
			t.Errorf("traverse (p = p->next, field_read source): tier = %q, want opaque-origin", c.NullOriginTier)
		}
	} else {
		t.Errorf("traverse: expected a candidate (post-advance p->y), got none")
	}
	if c, ok := byFn["deref_read_case"]; ok {
		if c.NullOriginTier != "opaque-origin" {
			t.Errorf("deref_read_case (r = *(int**)msg, deref_read source): tier = %q, want opaque-origin", c.NullOriginTier)
		}
	} else {
		t.Errorf("deref_read_case: expected a candidate, got none")
	}
}
