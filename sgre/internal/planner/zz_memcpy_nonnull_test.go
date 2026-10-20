//go:build !nosqlite

package planner

import "testing"

// The memcpy/str* copy family returns the caller-supplied dest pointer
// verbatim: the return value is an alias of dest, not an independent null
// source. A dereference of `p = memcpy(dst, src, n)` is a dereference of
// dst — if dst itself can be null, the dst variable's own candidate covers
// it. Seeding the RETURN value as a fail-open external call manufactures a
// duplicate candidate with a misleading tier.
func TestMemcpyFamilyReturnIsNonNull(t *testing.T) {
	src := `#include <string.h>

typedef struct { int x; } T;
static T g_a, g_b;

int use_memcpy_ret(void) {
    T *p = (T *)memcpy(&g_a, &g_b, sizeof(T));
    p->x = 1;
    return 0;
}

int use_strcat_ret(char *dst) {
    char *p = strcat(dst, "x");
    p[0] = 'y';
    return 0;
}
`
	result := runRetStrengthPlan(t, map[string]string{"memcpy_ret.c": src})

	for _, fn := range []string{"use_memcpy_ret", "use_strcat_ret"} {
		if c, ok := candidateByFunction(result, fn); ok {
			t.Errorf("%s: the copy-family return value must not seed a null-deref candidate (tier=%q)", fn, c.NullOriginTier)
		}
		if !droppedByFunction(result, fn) {
			t.Errorf("%s: expected the candidate to be dropped by the nullable-source filter", fn)
		}
	}
}
