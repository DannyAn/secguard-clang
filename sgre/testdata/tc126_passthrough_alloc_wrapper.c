/*
 * TC126 - Wrapper function returns a malloc'd pointer under a CUSTOM name (no
 * "alloc"/"malloc"/"new"/"dup" substring). The "封装成函数" production pattern
 * (docs/req_内存分配释放典型性优化.md): the wrapper NULL-checks and zero-
 * initializes before returning the pointer, so a caller that never frees the
 * result is a leak and a caller that frees it is a release pair.
 */

#include <stdlib.h>

/* custom name: no alloc/malloc/new/dup substring */
void *get_buffer(size_t n) {
    void *p = malloc(n);
    if (!p) return NULL;
    memset(p, 0, n); /* uses p between malloc and return — still an allocator */
    return p;
}

int tc126_wrapper_leak(int n) {
    char *buf = (char *)get_buffer((size_t)n);
    if (!buf) return -1;
    return buf[0];
}

int tc126_wrapper_free(int n) {
    char *buf = (char *)get_buffer((size_t)n);
    if (!buf) return -1;
    free(buf);
    return 0;
}
