/* tc116_ptr_arith_deref.c — NE-01 regression: a pointer-arithmetic dereference
 * (`*(p+1)`) of a definite-null pointer must resolve the base pointer `p` as
 * the dereferenced variable, so the null source reaches it. */
#include <stdlib.h>

typedef struct { int x; } T;

void ptr_arith_definite(void) {
    T *p = NULL;
    *(p+1) = 0;
}