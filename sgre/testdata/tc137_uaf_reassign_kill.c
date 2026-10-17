/*
 * TC137 - use-after-free: an unconditional whole-variable reassignment of a
 * DIFFERENT value between the free and the use kills the dangling state.
 * `free(p); p = &other; use(p)` uses the new object, not the freed one. A
 * reassignment whose RHS mentions the freed variable (`p = p->next`) or that
 * sits inside a runtime branch does not kill — those keep the candidate.
 */

#include <stdlib.h>

struct Node {
    struct Node *next;
    int v;
};

/* Unconditional reassign to a fresh object → NOT a use-after-free. */
void kill_reassign_ok(int *fallback) {
    int *a = (int *)malloc(16 * sizeof(int));
    free(a);
    a = fallback;
    a[0] = 1;
}

/* No reassignment → still a use-after-free. */
void no_reassign_still_uaf(void) {
    int *p = (int *)malloc(16 * sizeof(int));
    free(p);
    p[0] = 1;
}

/* RHS mentions the freed variable (classic linked-list traversal shape) →
 * NOT killed, still a use-after-free. */
void self_rhs_not_killed(void) {
    struct Node *p = (struct Node *)malloc(sizeof(struct Node));
    free(p);
    p = p->next;
    p->v = 1;
}

/* Reassignment inside a branch leaves the fall-through path dangling →
 * NOT killed, still a use-after-free. */
void branch_reassign_not_killed(int c, int *fallback) {
    int *p = (int *)malloc(16 * sizeof(int));
    free(p);
    if (c) {
        p = fallback;
    }
    p[0] = 1;
}