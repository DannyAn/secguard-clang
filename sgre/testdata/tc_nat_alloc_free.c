#include <stdlib.h>

/* User wrapper pair: the bottom layer (VOS_MALLOC/VOS_FREE) is a third-party
 * SDK macro outside the scan tree, so only the naming heuristic can recognize
 * nat_malloc/nat_free. A malloc + nat_free must NOT be a leak. */

void *nat_malloc(size_t n) {
    return VOS_MALLOC(n);
}

void nat_free(void *p) {
    VOS_FREE(p);
}

int tc_nat_alloc_free(int n) {
    int *buf = (int *)malloc(sizeof(int) * n);
    if (!buf) {
        return -1;
    }
    buf[0] = 42;
    nat_free(buf);
    return 0;
}
