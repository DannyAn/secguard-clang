/*
 * TC80 - Memory Leak: Unreachable Free (definite leak)
 * The free is dead code after an unconditional return, so the allocation
 * is definitely lost. canReachAnyRelease returns false -> definite=true
 * -> planner auto-confirms without sending to AI.
 */

#include <stdlib.h>

void tc80_unreachable_free(void) {
    char *p = (char *)malloc(100);
    if (!p) return;
    p[0] = 'x';
    return;
    free(p);
}
