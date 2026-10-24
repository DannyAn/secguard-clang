//go:build !nosqlite

package planner

import "testing"

// TestNullDeref_GuardForms locks the two guard forms a production MAF scan
// proved auto-confirmable false positives (both were machine-confirmed before
// the fix): the ternary inline guard and the unlikely()-wrapped early return.
func TestNullDeref_GuardForms(t *testing.T) {
	t.Run("ternary-guard-should-not-confirm", func(t *testing.T) {
		src := `struct rate_limiter { int action; };
struct maf_profile { struct rate_limiter rate_limiter; };

__attribute__((noinline)) struct maf_profile *maf_get_profile_by_id(unsigned int profile_id)
{
    if (profile_id == 0) {
        return NULL;
    }
    static struct maf_profile s;
    return &s;
}

int maf_get_rate_limiter_action(unsigned int profile_id)
{
    struct maf_profile *profile = maf_get_profile_by_id(profile_id);
    return (profile != NULL ? profile->rate_limiter.action : 0);
}
`
		res := planNullDerefSrc(t, src)
		for _, c := range res.Candidates {
			t.Logf("candidate: fn=%s var=%s line=%d tier=%s suspicion=%s hint=%s",
				c.Target.Function, c.Target.Variable, c.Target.Line, c.NullOriginTier, c.SuspicionLevel, c.Hint)
		}
		if n := len(res.Candidates); n != 0 {
			c := res.Candidates[0]
			t.Errorf("ternary guard: got %d candidate(s), first: fn=%s var=%s tier=%s suspicion=%s — REPORT CLAIM CONFIRMED (false auto-confirm)",
				n, c.Target.Function, c.Target.Variable, c.NullOriginTier, c.SuspicionLevel)
		}
	})

	t.Run("unlikely-if-return-guard-should-not-confirm", func(t *testing.T) {
		src := `#define unlikely(x) (__builtin_expect(!!(x), 0))

struct time_slot { long start_time_ms; int count; };

__attribute__((noinline)) struct time_slot *maf_new_time_slot(long now_ms)
{
    if (now_ms == 0) {
        return NULL;
    }
    static struct time_slot s;
    return &s;
}

int maf_rate_limit(struct time_slot **out, long now_ms)
{
    struct time_slot *slot = maf_new_time_slot(now_ms);
    if (unlikely(slot == NULL)) {
        return 0;
    }
    slot->count++;
    return 1;
}
`
		res := planNullDerefSrc(t, src)
		for _, c := range res.Candidates {
			t.Logf("candidate: fn=%s var=%s line=%d tier=%s suspicion=%s hint=%s",
				c.Target.Function, c.Target.Variable, c.Target.Line, c.NullOriginTier, c.SuspicionLevel, c.Hint)
		}
		if n := len(res.Candidates); n != 0 {
			c := res.Candidates[0]
			t.Errorf("unlikely guard: got %d candidate(s), first: fn=%s var=%s tier=%s suspicion=%s — REPORT CLAIM CONFIRMED (false auto-confirm)",
				n, c.Target.Function, c.Target.Variable, c.NullOriginTier, c.SuspicionLevel)
		}
	})

	t.Run("plain-if-return-guard-baseline", func(t *testing.T) {
		src := `struct time_slot { long start_time_ms; int count; };

__attribute__((noinline)) struct time_slot *maf_new_time_slot(long now_ms)
{
    if (now_ms == 0) {
        return NULL;
    }
    static struct time_slot s;
    return &s;
}

int maf_rate_limit(struct time_slot **out, long now_ms)
{
    struct time_slot *slot = maf_new_time_slot(now_ms);
    if (slot == NULL) {
        return 0;
    }
    slot->count++;
    return 1;
}
`
		res := planNullDerefSrc(t, src)
		if n := len(res.Candidates); n != 0 {
			t.Errorf("plain guard baseline: got %d candidate(s) — guard model broken?", n)
		}
	})
}
func TestNullDeref_GuardFormsNoFalseNegative(t *testing.T) {
	t.Run("ternary-guards-other-var-still-reported", func(t *testing.T) {
		src := `#include <stdlib.h>
struct s { int a; };

int f(int q)
{
    struct s *p = malloc(sizeof *p);
    int r = (q != 0 ? p->a : 0);
    return r;
}
`
		res := planNullDerefSrc(t, src)
		if n := len(res.Candidates); n == 0 {
			t.Errorf("ternary guarding a DIFFERENT variable must not suppress p deref — false negative introduced")
		}
	})

	t.Run("ternary-null-branch-deref-still-reported", func(t *testing.T) {
		src := `#include <stdlib.h>
struct s { int a; };

int f(void)
{
    struct s *p = malloc(sizeof *p);
    return (p == NULL ? p->a : 0);
}
`
		res := planNullDerefSrc(t, src)
		if n := len(res.Candidates); n == 0 {
			t.Errorf("p == NULL ? p->a : d dereferences p on the NULL path — must stay a candidate")
		}
	})

	t.Run("likely-wrapped-positive-guard-suppresses", func(t *testing.T) {
		src := `#define likely(x) (__builtin_expect(!!(x), 1))

struct s { int a; };
struct s *get(void) { static struct s v; return &v; }

int f(void)
{
    struct s *p = get();
    if (likely(p != NULL)) {
        return p->a;
    }
    return 0;
}
`
		res := planNullDerefSrc(t, src)
		if n := len(res.Candidates); n != 0 {
			t.Errorf("likely(p != NULL) true branch is guarded: got %d candidate(s)", n)
		}
	})

	t.Run("builtin-expect-wrapped-guard-suppresses", func(t *testing.T) {
		src := `struct s { int a; };

int f(struct s *p, int mode)
{
    if (__builtin_expect(!!(p == NULL), 0)) {
        return -1;
    }
    return p->a;
}
`
		res := planNullDerefSrc(t, src)
		if n := len(res.Candidates); n != 0 {
			t.Errorf("__builtin_expect(!!(p == NULL), 0) fall-through is guarded: got %d candidate(s)", n)
		}
	})

	// The redis `hashslot ? *hashslot : INVALID_CLUSTER_SLOT` shape: a ternary
	// truthiness guard protects a caller-null PARAMETER's dereference. The
	// parameter has no positioned source (SourceLine 0) and its entry seed is
	// definite, but the ternary branch still guarantees non-null on that path —
	// it must not auto-confirm.
	t.Run("ternary-guard-caller-null-param", func(t *testing.T) {
		src := `int f(int *p)
{
    int slot = p ? *p : -1;
    return slot;
}
`
		res := planNullDerefFullSrc(t, src)
		for _, c := range res.Candidates {
			t.Logf("candidate: fn=%s var=%s line=%d tier=%s suspicion=%s hint=%s",
				c.Target.Function, c.Target.Variable, c.Target.Line, c.NullOriginTier, c.SuspicionLevel, c.Hint)
		}
		if n := len(res.Candidates); n != 0 {
			c := res.Candidates[0]
			t.Errorf("ternary truthiness guard on a caller-null param: got %d candidate(s), first: fn=%s var=%s suspicion=%s",
				n, c.Target.Function, c.Target.Variable, c.SuspicionLevel)
		}
	})
}
