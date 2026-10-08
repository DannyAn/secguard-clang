/*
 * TC81 - Memory Leak: Conditional Branch Free (suspected, not definite)
 * The free is reachable on the error path but the normal path leaks.
 * canReachAnyRelease returns true -> not definite -> stays suspected for AI.
 */

#include <stdlib.h>

void tc81_cond_branch_free(int err) {
    char *p = (char *)malloc(100);
    if (!p) return;
    if (err) {
        free(p);
        return;
    }
    p[0] = 'y';
}
