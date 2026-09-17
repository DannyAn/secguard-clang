#include <stdlib.h>

/* nat_malloc is a project allocator wrapper (calls the external VOS_MALLOC
 * macro). A nat_malloc result that is never freed must be detected as a leak. */

void *nat_malloc(size_t n) {
    return VOS_MALLOC(n);
}

int tc_nat_alloc_leak(int n) {
    int *buf = (int *)nat_malloc(sizeof(int) * n);
    if (!buf) {
        return -1;
    }
    buf[0] = 42;
    return buf[0];
}
