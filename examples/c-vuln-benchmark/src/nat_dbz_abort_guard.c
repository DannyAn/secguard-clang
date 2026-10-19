/*
 * NAT production round-2 regression (CWE-369)
 *
 * P19-03: an init-function abort-guard establishes the divisor as non-zero —
 *         `if (n == 0) { HPE_ASSERT(0); } g_max_sess = n;` where HPE_ASSERT's
 *         #define body calls abort(). The surviving path never sees zero, so
 *         the cross-function division must NOT be flagged.
 * P19-04: the guard may sit on the global itself — `if (g_min_sess == 0)
 *         { exit(1); }` proves g_min_sess non-zero with no propagating
 *         assignment. Must NOT be flagged.
 *
 * The dbz_real control (unguarded parameter divisor) stays flagged.
 */

#include <stdlib.h>
#include <stdio.h>

#define HPE_ASSERT(x) do { if (!(x)) { (void)printf("fail"); abort(); } } while (0)

int g_max_sess;
int g_min_sess;

void nat_init_a(int cfg) {
    int n = cfg * 2;
    if (n == 0) { HPE_ASSERT(0); }
    g_max_sess = n;
}

void nat_init_b(int cfg) {
    g_min_sess = cfg;
    if (g_min_sess == 0) { exit(1); }
}

unsigned long nat_avg_a(unsigned long total) { return total / g_max_sess; }

unsigned long nat_avg_b(unsigned long total) { return total / g_min_sess; }

/* dbz_real is the must-stay-flagged control. Keep it >3 lines from the
 * guarded divisions above: the benchmark validator matches findings with a
 * ±3 line tolerance, and P19-03/P19-04 sit at the two division lines. */
unsigned long dbz_real(int d) { return 100 / d; }