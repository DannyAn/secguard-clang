#include <stdlib.h>

static void *sg_test_never_null_malloc(size_t n) {
    return malloc(n);
}

static void *sg_test_never_null_wrapper(size_t n) {
    return sg_test_never_null_malloc(n);
}

void call_never_null_unchecked(void) {
    void *p = sg_test_never_null_malloc(64);
    p[0] = 'x';
}

void call_never_null_wrapper_unchecked(void) {
    void *p = sg_test_never_null_wrapper(64);
    p[0] = 'x';
}

void call_real_alloc_checked(void) {
    void *p = malloc(64);
    if (!p) return;
    p[0] = 'x';
}