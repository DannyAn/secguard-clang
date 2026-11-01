/*
 * TC181 - use-after-free: a bare `return p` reads the pointer VALUE and hands
 * it out; it does NOT dereference the freed object. That is a dangling-pointer
 * escape (the caller dereferences the dangling value), not a use-after-free.
 * The detector must NOT flag it (P1-5): counting `return p` as a use made
 * `free(p); return p;` a false positive that also duplicated the caller's
 * double-free.
 */

#include <stdlib.h>

struct Node { int v; };

/* free + return the dangling pointer → NOT a use-after-free here. */
struct Node *make_ptr(void) {
    struct Node *q = (struct Node *)malloc(sizeof(struct Node));
    free(q);
    return q;
}

/* A real use-after-free: dereference after free. */
int real_uaf_deref(void) {
    struct Node *p = (struct Node *)malloc(sizeof(struct Node));
    free(p);
    return p->v;
}
