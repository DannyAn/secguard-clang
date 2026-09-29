//go:build !nosqlite

package planner

import (
	"testing"
)

// TestNullDeref_AssertGuard pins the assert-guard idiom: assert(p != NULL)
// establishes p non-null on the fall-through, so a dereference after the assert
// must not be flagged as null-deref. Covers three assert forms:
//  1. assert(p != NULL) — explicit non-null check
//  2. assert(p)         — truthiness check
//  3. assert(p != NULL && q != NULL) — conjunction, both guarded
//
// The no-guard control must still produce a candidate.
func TestNullDeref_AssertGuard(t *testing.T) {
	src := `#include <stdlib.h>
extern void assert(int expr);

void assert_guard_malloc(void)
{
    int *p = malloc(sizeof(int));
    assert(p != NULL);
    *p = 1;
}

void assert_truthiness_malloc(void)
{
    int *p = malloc(sizeof(int));
    assert(p);
    *p = 1;
}

void assert_and_guard_malloc(void)
{
    int *p = malloc(sizeof(int));
    int *q = malloc(sizeof(int));
    assert(p != NULL && q != NULL);
    *p = 1;
    *q = 2;
}

void no_guard_malloc(void)
{
    int *p = malloc(sizeof(int));
    *p = 1;
}
`
	result := planNullDerefGuardExit(t, src)

	byFunc := map[string]int{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function]++
	}

	if byFunc["assert_guard_malloc"] > 0 {
		t.Errorf("assert_guard_malloc: expected 0 candidates (assert guard), got %d", byFunc["assert_guard_malloc"])
	}
	if byFunc["assert_truthiness_malloc"] > 0 {
		t.Errorf("assert_truthiness_malloc: expected 0 candidates (assert truthiness guard), got %d", byFunc["assert_truthiness_malloc"])
	}
	if byFunc["assert_and_guard_malloc"] > 0 {
		t.Errorf("assert_and_guard_malloc: expected 0 candidates (assert && guard), got %d", byFunc["assert_and_guard_malloc"])
	}
	if byFunc["no_guard_malloc"] == 0 {
		t.Error("no_guard_malloc: expected >0 candidates (no guard), got 0")
	}
}

// ND-08: `assert(p != err0)` compares p against a non-null sentinel, so it does
// NOT establish p non-null and must not suppress the following dereference.
func TestNullDeref_AssertNotGuardErr0(t *testing.T) {
	src := `#include <stdlib.h>
extern void assert(int expr);
int err0;

void assert_err0_malloc(void)
{
    int *p = malloc(sizeof(int));
    assert(p != err0);
    *p = 1;
}
`
	result := planNullDerefGuardExit(t, src)
	if c := candidateForFunc(t, result, "assert_err0_malloc"); c == nil {
		t.Errorf("assert_err0_malloc should STAY flagged (assert(p != err0) does not prove p non-null)")
	}
}
