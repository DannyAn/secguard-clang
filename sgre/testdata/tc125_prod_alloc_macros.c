/*
 * TC125 - Production allocator/free macro wrappers (nlog/nat pattern from
 * docs/req_内存分配释放典型性优化.md). A macro that expands to malloc/free or a
 * third-party SDK allocator must be treated as alloc/free: an unfreed allocation
 * through the macro is a leak, and a macro-free is a release (not a leak).
 */

#include <stdlib.h>

#define nlog_malloc(mid, size) malloc((size))
#define nlog_free(ptr) free(ptr)

#define NAT_MALLOC(mid, size) HpeMemAlloc((mid), (size))
#define NAT_FREE(buf) HpeMemFree(buf)

/* Third-party SDK allocator stubs (outside the scan tree). */
void *HpeMemAlloc(int mid, size_t size) { (void)mid; return malloc(size); }
void HpeMemFree(void *p) { free(p); }

/* macro -> malloc, then macro -> free: a release pair, NOT a leak. */
int tc125_macro_alloc_free(int n) {
    int *buf = (int *)nlog_malloc(1, sizeof(int) * n);
    if (!buf) return -1;
    buf[0] = 1;
    nlog_free(buf);
    return 0;
}

/* macro -> HpeMemAlloc, never freed: a leak. */
int tc125_macro_alloc_leak(int n) {
    int *buf = (int *)NAT_MALLOC(1, sizeof(int) * n);
    if (!buf) return -1;
    return buf[0];
}

/* Direct third-party SDK allocator (VOS_Malloc_F), never freed: a leak. */
int tc125_sdk_direct_leak(int n) {
    char *p = (char *)VOS_Malloc_F(1, (size_t)n);
    if (!p) return -1;
    return p[0];
}

/* Direct SDK allocator + SDK free: a release pair, NOT a leak. */
int tc125_sdk_direct_free(int n) {
    char *p = (char *)VOS_Mem_Allock_F(1, (size_t)n);
    if (!p) return -1;
    VOS_MemFree_F(p);
    return 0;
}
