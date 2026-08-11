/*
 * TC13 - Uninit: Calloc Safe/Zeroed (REQ-TC-013)
 * Safe pattern: calloc'd memory is zero-initialized by the C standard.
 * Expected: NO finding (REQ-TDD-005)
 */

#include <stdlib.h>

int tc13_uninit_calloc_safe(int n) {
    int *p = (int *)calloc(n, sizeof(int));
    if (!p) {
        return -1;
    }
    int v = p[0];
    free(p);
    return v;
}