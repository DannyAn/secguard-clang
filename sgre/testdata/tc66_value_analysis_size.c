#include <stdlib.h>

void overflow_mul_const(int n) {
    char *p = malloc(n * 1024); /* INTEGER_OVERFLOW: n * 1024 can wrap */
    if (p) free(p);
}

void overflow_calloc(int n, int m) {
    char *p = calloc(n, m); /* INTEGER_OVERFLOW: n * m can wrap */
    if (p) free(p);
}

void safe_add_const(size_t n) {
    char *p = malloc(n + 1); /* safe: n + 1 null-terminator idiom, not overflow */
    if (p) free(p);
}

void safe_sub_const(size_t n) {
    char *p = malloc(n - 1); /* safe: n - 1 off-by-one idiom, not overflow */
    if (p) free(p);
}

void safe_mul_small_const(size_t n) {
    char *p = malloc(n * 4); /* safe: n * 4 small multiplier, implausible overflow */
    if (p) free(p);
}

void safe_local_add(void) {
    size_t n = 16;
    char *p = malloc(n + 1); /* safe: n is a bounded local, not caller-influenced */
    if (p) free(p);
}
