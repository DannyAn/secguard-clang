#include <stdlib.h>

static void fill(int *out) {
    *out = 1;
}

/* Two same-named local `v` in different blocks, each initialized through an
 * output parameter and then used. Scope-insensitive tracking (keying facts by
 * bare name) let the second block's init line suppress the first block's use,
 * a false positive. Each `v` must resolve to its own declaration. */
int scope_shadow_init(int *p, int *q) {
    int result = 0;
    if (p) {
        int v;
        fill(&v);
        result += v;
    }
    if (q) {
        int v;
        fill(&v);
        result += v;
    }
    return result;
}

/* A name shadowed in an inner block: the inner `v` is genuinely uninitialized
 * and must still be reported, while the outer `v` is initialized via fill(). */
int scope_shadow_genuine(int *q) {
    int v;
    fill(&v);
    int result = v;
    if (q) {
        int v;
        result += v;
    }
    return result;
}