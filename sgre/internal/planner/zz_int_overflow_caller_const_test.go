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
