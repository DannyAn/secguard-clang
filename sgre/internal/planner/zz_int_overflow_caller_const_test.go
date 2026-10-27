//go:build !nosqlite

package planner

import "testing"

// NLOG pattern 6: `(sizeof(T) + sizeof(int)) * num` where num's ONLY caller
// passes a compile-time integer constant. The size-calc integer-overflow
// candidate must be dropped — the sizeof terms are compile-time constants and
// the parameter is provably bounded across the whole tree. Two pre-existing
// gaps blocked this: (1) the callsite census had no caller-constant bound, and
// (2) identifiersInExpr collected the sizeof TYPE name (a typedef) as a
// "variable operand" that no bound could satisfy.
func TestIntOverflow_CallerConstantDropsSizeCalc(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>
typedef struct { int data[16]; } PoolEntry;
void *pool_create(uint32_t num) {
    size_t total = (sizeof(PoolEntry) + sizeof(int)) * num;
    return malloc(total);
}
void caller(void) {
    void *p = pool_create(64);
    (void)p;
}
`
	res := planType(t, src, "integer-overflow")
	if c, ok := res["pool_create"]; ok {
		t.Errorf("pool_create: the only caller passes the constant 64, the product cannot overflow — must not be a candidate (hint=%v)", c.Hint)
	}
}

// Control: a caller passing a parameter keeps the candidate (the value is
// unbounded, so overflow is possible).
func TestIntOverflow_CallerParameterKeepsSizeCalc(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>
typedef struct { int data[16]; } PoolEntry;
void *pool_create(uint32_t num) {
    size_t total = (sizeof(PoolEntry) + sizeof(int)) * num;
    return malloc(total);
}
void caller(uint32_t n) {
    void *p = pool_create(n);
    (void)p;
}
`
	res := planType(t, src, "integer-overflow")
	if _, ok := res["pool_create"]; !ok {
		t.Errorf("pool_create: the caller passes a parameter, the product can overflow — must stay a candidate")
	}
}

// NLOG TC-6a side finding: `void *p = f(); (void)p;` deliberately discards the
// result, so the "unchecked return" is NOT a defect (the failure is unobservable).
// The candidate's own verdict fact says "dismiss", and command-instructions.md
// lists `discard` as a DISMISS hint — yet ReturnCheckFilter promoted it to
// confirmed (a machine-confirmed CWE-252 false positive). A discard must stay a
// suspected lead, never auto-confirm.
func TestUncheckedReturn_DiscardNotAutoConfirmed(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>
typedef struct { int data[16]; } PoolEntry;
void *pool_create(uint32_t num) {
    size_t total = (sizeof(PoolEntry) + sizeof(int)) * num;
    return malloc(total);
}
void caller(void) {
    void *p = pool_create(64);
    (void)p;
}
`
	res := planType(t, src, "unchecked-return")
	c, ok := res["caller"]
	if !ok {
		t.Fatalf("the discard lead should still be a candidate")
	}
	if c.SuspicionLevel == "confirmed" {
		t.Errorf("a (void)-discarded return must not be auto-confirmed (hint=%v)", c.Hint)
	}
}

// Control: an allocator result that is stored and then USED without a NULL check
// is a genuine CWE-252 defect and must still be promoted to confirmed.
func TestUncheckedReturn_UsedWithoutCheckStillConfirmed(t *testing.T) {
	src := `#include <stdlib.h>
#include <string.h>
void copy_it(const char *s) {
    char *dst = malloc(64);
    strcpy(dst, s);
    free(dst);
}
`
	res := planType(t, src, "unchecked-return")
	c, ok := res["copy_it"]
	if !ok {
		t.Fatalf("expected an unchecked-return candidate for copy_it")
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("a used-but-unchecked malloc must be confirmed, got %q", c.SuspicionLevel)
	}
}
