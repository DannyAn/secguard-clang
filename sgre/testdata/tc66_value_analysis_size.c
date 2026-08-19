#include <stdlib.h>

void overflow_add_const(size_t n) {
    char *p = malloc(n + 1); /* INTEGER_OVERFLOW: n + 1 wraps when n == SIZE_MAX */
    if (p) free(p);
}

void overflow_mul_const(size_t n) {
    char *p = malloc(n * 4); /* INTEGER_OVERFLOW: n * 4 can wrap */
    if (p) free(p);
}

void overflow_calloc(size_t n, size_t m) {
    char *p = calloc(n, m); /* INTEGER_OVERFLOW: n * m can wrap */
    if (p) free(p);
}

void overflow_sub_const(size_t n) {
    char *p = malloc(n - 1); /* INTEGER_OVERFLOW: n - 1 wraps under 0 */
    if (p) free(p);
}

void safe_local_add(void) {
    size_t n = 16;
    char *p = malloc(n + 1); /* safe: n is a bounded local, not caller-influenced */
    if (p) free(p);
}
