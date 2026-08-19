#include <stdlib.h>
#include <string.h>

void overflow_sizeof_alloc(int n) {
    char *p = malloc(n * sizeof(int)); /* INTEGER_OVERFLOW: n * sizeof(int) can overflow */
    if (p == NULL) return;
    free(p);
}

void safe_var_var_alloc(int m, int n) {
    char *p = malloc(m * n); /* INTEGER_OVERFLOW: two-variable product */
    if (p == NULL) return;
    free(p);
}

void safe_constant_alloc(void) {
    char *p = malloc(256); /* safe: constant */
    if (p == NULL) return;
    free(p);
}