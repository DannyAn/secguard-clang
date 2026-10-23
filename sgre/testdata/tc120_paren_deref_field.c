/* tc120_paren_deref_field.c — ND-09 regression: `(*p).x` is a dereference of
 * p (the `p->x` equivalent with a parenthesized base). */
#include <stdlib.h>

typedef struct { int x; } T;

void paren_deref(void) {
    T *p = NULL;
    (*p).x = 1;
}