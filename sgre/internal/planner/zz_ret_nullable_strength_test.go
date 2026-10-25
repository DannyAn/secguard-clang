//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// The proven/assumed nullability split: a callee whose body PROVABLY returns
// NULL (literal `return NULL`, an allocator result) is a proven-nullable origin
// and auto-confirms its unchecked call-site dereference; a callee whose
// nullability is only a fail-open assumption (field read, unknown external
// forward, pointer parameter) stays suspected under the `assumed-return` tier.
const retStrengthFixture = `#include <stdlib.h>

typedef struct { int x; } T;
static T g_var;
static struct { T *field; } g_holder = {0};

extern T *external_get(void);
extern int external_count(void);

/* int-returning function with a literal zero return: the return type gates the
 * null seed — the integer zero is not a null pointer. */
int int_zero(void) { return 0; }

/* PROVEN nullable: a literal NULL return path exists. */
T *proven_getter(int c) {
    if (c) { return NULL; }
    return &g_var;
}

/* ASSUMED nullable: returns a field read (zero-initialized, fail-open). */
T *assumed_field_getter(void) {
    return g_holder.field;
}

/* ASSUMED nullable: forwards an unknown external call. */
T *assumed_external_getter(void) {
    return external_get();
}

/* PROVEN nullable: returns the allocator result (certain-tier source). */
T *proven_wrapper(void) {
    T *p = (T *)malloc(sizeof(T));
    return p;
}

int use_proven_getter(int c) {
    T *p = proven_getter(c);
    p->x = 1;
    return 0;
}

int use_assumed_field(void) {
    T *p = assumed_field_getter();
    p->x = 1;
    return 0;
}

int use_assumed_external(void) {
    T *p = assumed_external_getter();
    p->x = 1;
    return 0;
}

int use_proven_wrapper(void) {
    T *p = proven_wrapper();
    p->x = 1;
    return 0;
}

int use_int_zero(void) {
    T *q = (T *)int_zero();
    q->x = 1;
    return 0;
}
`

func runRetStrengthPlan(t *testing.T, files map[string]string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	var paths []string
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
		paths = append(paths, path)
	}

	idx := indexer.NewIndexer(store, logger)
	for _, path := range paths {
		if _, err := idx.Index(ctx, path); err != nil {
			t.Fatalf("index %s: %v", path, err)
		}
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

func candidateByFunction(r *PlanResult, fn string) (EvidenceItem, bool) {
	for _, c := range r.Candidates {
		if c.Target.Function == fn {
			return c, true
		}
	}
	return EvidenceItem{}, false
}

func droppedByFunction(r *PlanResult, fn string) bool {
	for _, d := range r.Summary.Dropped {
		if d.FunctionName == fn {
			return true
		}
	}
	return false
}

func TestRetNullableStrengthTiers(t *testing.T) {
	result := runRetStrengthPlan(t, map[string]string{"ret_strength.c": retStrengthFixture})

	// A proven-nullable callee (literal NULL return) keeps the malloc-fail tier
	// but is may-null, not must-null — suspected for the AI, never auto-confirmed.
	for _, fn := range []string{"use_proven_getter", "use_proven_wrapper"} {
		c, ok := candidateByFunction(result, fn)
		if !ok {
			t.Errorf("%s: expected a kept candidate, got candidates: %v (dropped=%v)", fn, candidateNames(result), droppedByFunction(result, fn))
			continue
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("%s: expected suspected (proven-nullable callee is a may-null), got %q", fn, c.SuspicionLevel)
		}
		if c.NullOriginTier != "malloc-fail" {
			t.Errorf("%s: expected tier malloc-fail, got %q", fn, c.NullOriginTier)
		}
	}

	// A fail-open callee (field read / unknown external forward) stays
	// suspected and is labelled with the assumed-return tier so the AI knows
	// the nullability is an assumption, not a proof.
	for _, fn := range []string{"use_assumed_field", "use_assumed_external"} {
		c, ok := candidateByFunction(result, fn)
		if !ok {
			t.Errorf("%s: expected a kept candidate, got candidates: %v (dropped=%v)", fn, candidateNames(result), droppedByFunction(result, fn))
			continue
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("%s: expected suspected (fail-open assumption), got %q", fn, c.SuspicionLevel)
		}
		if c.NullOriginTier != "assumed-return" {
			t.Errorf("%s: expected tier assumed-return, got %q", fn, c.NullOriginTier)
		}
	}

	// The int-returning `return 0` must not seed a null source at all: the
	// call-site dereference has no nullable source and is dropped.
	if c, ok := candidateByFunction(result, "use_int_zero"); ok {
		t.Errorf("use_int_zero: expected drop (int return type gates the null seed), got candidate with tier %q suspicion %q", c.NullOriginTier, c.SuspicionLevel)
	}
	if !droppedByFunction(result, "use_int_zero") {
		t.Error("use_int_zero: expected a recorded drop under nullable_source")
	}
}

// Same-name functions with conflicting nullability evidence merge
// conservatively: one proven definition plus one assumed definition resolves
// to ASSUMED at the name level, so neither call site auto-confirms.
func TestRetNullableSameNameConservativeMerge(t *testing.T) {
	fileA := `#include <stdlib.h>
typedef struct { int x; } T;
static T g_a;
static T *dup_name(int c) {
    if (c) { return NULL; }
    return &g_a;
}
int use_dup_a(int c) {
    T *p = dup_name(c);
    p->x = 1;
    return 0;
}
`
	fileB := `#include <stdlib.h>
typedef struct { int x; } T;
static struct { T *field; } g_holder_b = {0};
static T *dup_name(void) {
    return g_holder_b.field;
}
int use_dup_b(void) {
    T *p = dup_name();
    p->x = 1;
    return 0;
}
`
	result := runRetStrengthPlan(t, map[string]string{"a.c": fileA, "b.c": fileB})

	for _, fn := range []string{"use_dup_a", "use_dup_b"} {
		c, ok := candidateByFunction(result, fn)
		if !ok {
			t.Errorf("%s: expected a kept candidate, got candidates: %v (dropped=%v)", fn, candidateNames(result), droppedByFunction(result, fn))
			continue
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("%s: expected suspected (same-name merge is conservative), got %q", fn, c.SuspicionLevel)
		}
		if c.NullOriginTier != "assumed-return" {
			t.Errorf("%s: expected tier assumed-return (conservative merge), got %q", fn, c.NullOriginTier)
		}
	}
}

// NP-05: pointer arithmetic on a STATIC ARRAY base (`(T *)(g_arr + i * 8)`)
// is provably non-null — the result is an address inside (or one past) the
// array, never NULL. The cast's type_descriptor child used to be recursed
// into like a value, hit the fail-open default, and downgraded the whole cast
// to assumed — flooding the call site with a suspected candidate that should
// never exist.
func TestRetNullableStaticArrayBasePointerArithmetic(t *testing.T) {
	fixture := `typedef struct { int x; } T;
static char g_arr[256];

T *get_elem(int i) { return (T *)(g_arr + i * 8); }

void use(void) {
    T *p = get_elem(2);
    p->x = 1;
}
`
	result := runRetStrengthPlan(t, map[string]string{"np05.c": fixture})
	if c, ok := candidateByFunction(result, "use"); ok {
		t.Errorf("use: expected NO candidate (static-array base arithmetic is provably non-null), got tier %q suspicion %q", c.NullOriginTier, c.SuspicionLevel)
	}
}

// NP-01: a caller_null source (a caller passing a literal NULL to a
// parameter) seeds at the FUNCTION DEFINITION line (fn.StartLine), but the
// fixpoint analyzer in computeRetNullable never populated entrySeeds — it
// passed the sources through nullGenByLine, which buckets by line, and the
// body's first statement sits at a different line, so the source never
// landed on any CFG node. A callee that derives a local from a caller-null
// parameter and returns it (`T *q = p; return q;`) was misjudged notNull,
// silently dropping every call-site dereference.
func TestRetNullableDerivedLocalReturnFromCallerNullParam(t *testing.T) {
	fixture := `#include <stdlib.h>
typedef struct { int x; } T;

T *callee(T *p) {
    T *q = p;
    return q;
}

void caller(void) {
    T *r = callee(NULL);
    r->x = 1;
}
`
	result := runOpaqueNullPlan(t, map[string]string{"np01.c": fixture})
	c, ok := candidateByFunction(result, "caller")
	if !ok {
		t.Errorf("caller: expected a kept candidate (callee returns a local derived from caller-null param), got candidates: %v (dropped=%v)", candidateNames(result), droppedByFunction(result, "caller"))
		return
	}
	if c.SuspicionLevel == "" {
		t.Errorf("caller: expected a non-empty SuspicionLevel, got candidate %+v", c)
	}
}

// NP-01 sibling shape: a caller_null source seeded via a non-literal NULL
// witness (unproven caller) must still reach the fixpoint — the callee is
// nullable (assumed tier), not silently notNull.
func TestRetNullableDerivedLocalReturnFromUnprovenCallerParam(t *testing.T) {
	fixture := `#include <stdlib.h>
typedef struct { int x; } T;

T *callee(T *p) {
    T *q = p;
    return q;
}

void intermediate(T *w) {
    T *r = callee(w);
    r->x = 1;
}
`
	result := runOpaqueNullPlan(t, map[string]string{"np01b.c": fixture})
	c, ok := candidateByFunction(result, "intermediate")
	if !ok {
		t.Errorf("intermediate: expected a kept candidate (callee returns a local derived from caller param), got candidates: %v (dropped=%v)", candidateNames(result), droppedByFunction(result, "intermediate"))
		return
	}
	if c.SuspicionLevel == "" {
		t.Errorf("intermediate: expected a non-empty SuspicionLevel, got candidate %+v", c)
	}
}
