#include <stdlib.h>

/* --- positive: implicit calloc product (CWE-190) --- */
void calloc_var_sizeof(int n) {
    char *p = calloc(n, sizeof(int)); /* size_calc_overflow */
    if (p == NULL) return;
    free(p);
}

void calloc_sizeof_var(int n) {
    char *p = calloc(sizeof(int), n); /* size_calc_overflow (arg order swapped) */
    if (p == NULL) return;
    free(p);
}

void calloc_param_const(int n) {
    char *p = calloc(n, 4); /* size_mul_const_overflow */
    if (p == NULL) return;
    free(p);
}

void calloc_const_param(int n) {
    char *p = calloc(8, n); /* size_mul_const_overflow (arg order swapped) */
    if (p == NULL) return;
    free(p);
}

void calloc_var_var(int n, int m) {
    char *p = calloc(n, m); /* size_calc_overflow */
    if (p == NULL) return;
    free(p);
}

/* --- positive: explicit malloc product (existing coverage) --- */
void malloc_var_sizeof(int n) {
    char *p = malloc(n * sizeof(int)); /* size_calc_overflow */
    if (p == NULL) return;
    free(p);
}

/* --- negative: constants / sizeof(char)==1 / const<=1 cannot overflow --- */
void calloc_const_const(void) {
    char *p = calloc(10, 20); /* safe: constant * constant */
    if (p == NULL) return;
    free(p);
}

void calloc_const_sizeof(void) {
    char *p = calloc(10, sizeof(int)); /* safe: constant * sizeof */
    if (p == NULL) return;
    free(p);
}

void calloc_var_sizeof_char(int n) {
    char *p = calloc(n, sizeof(char)); /* safe: n * 1 */
    if (p == NULL) return;
    free(p);
}

void calloc_var_const_one(int n) {
    char *p = calloc(n, 1); /* safe: n * 1 */
    if (p == NULL) return;
    free(p);
}

void malloc_constant(void) {
    char *p = malloc(256); /* safe: constant */
    if (p == NULL) return;
    free(p);
}
