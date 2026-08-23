#include <stdlib.h>
#include <string.h>

typedef char *cstr_t;

void safe_sizeof_deref(int n) {
    int *p = malloc(n * sizeof(*p)); /* safe: sizeof(*p) */
    memset(p, 0, n * sizeof(*p));    /* safe */
    free(p);
}

void unsafe_sizeof_pointer(int n) {
    char **p = malloc(n * sizeof(p)); /* SIZEOF_MISUSE: sizeof(p) = pointer width */
    (void)p;
}

void unsafe_sizeof_single_pointer(int n) {
    char *q = malloc(n * sizeof(q)); /* SIZEOF_MISUSE (confirmed): sizeof(q), not sizeof(*q) */
    (void)q;
}

void ambig_sizeof_pointer_typedef(int n) {
    cstr_t *s = malloc(n * sizeof(s)); /* SIZEOF_MISUSE (suspected): cstr_t is char*, so s is char** */
    (void)s;
}

void unsafe_memset_sizeof_pointer(char *buf, int n) {
    memset(buf, 0, sizeof(buf)); /* SIZEOF_MISUSE: sizeof(buf) = pointer width */
    (void)n;
}
