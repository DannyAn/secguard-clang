#include <stdlib.h>
#include <string.h>

void safe_sizeof_deref(int n) {
    int *p = malloc(n * sizeof(*p)); /* safe: sizeof(*p) */
    memset(p, 0, n * sizeof(*p));    /* safe */
    free(p);
}

void unsafe_sizeof_pointer(int n) {
    char **p = malloc(n * sizeof(p)); /* SIZEOF_MISUSE: sizeof(p) = pointer width */
    (void)p;
}

void unsafe_memset_sizeof_pointer(char *buf, int n) {
    memset(buf, 0, sizeof(buf)); /* SIZEOF_MISUSE: sizeof(buf) = pointer width */
    (void)n;
}
