/* tc110: overwritten pointer (lost allocation) must still be reported. */
#include <stdlib.h>

/* Both allocations lost: p is reassigned without freeing the first block. */
void overwrite_no_free(void) {
    char *p = malloc(100);
    p = malloc(200);
}

/* First allocation lost, second freed: one leak, not zero. */
void overwrite_then_free(void) {
    char *p = malloc(100);
    p = malloc(200);
    free(p);
}

/* A non-malloc overwrite (p = NULL) also drops the previous allocation. */
void overwrite_with_null(void) {
    char *p = malloc(100);
    p = NULL;
}

/* Plain single allocation with no free (control). */
void single_no_free(void) {
    char *p = malloc(100);
}

/* Declaration-then-assignment form: p is a pointer LOCAL; `p = malloc()` on a
 * later line must still be a leak (not misread as an escape to a global). */
void decl_then_assign(void) {
    char *p;
    p = malloc(100);
}
