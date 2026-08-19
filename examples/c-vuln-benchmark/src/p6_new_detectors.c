/*
 * P6 — 新增 5 类检测器 (divide-by-zero / unchecked-return / path-traversal /
 * sizeof-misuse / signed-compare) 的基准用例。
 *
 * 每类一对：一个真阳性（应报告 finding）+ 一个安全模式（应被收敛为
 * no_finding），锁定新增检测器的召回与精度。
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/* ---- divide-by-zero (CWE-369) ---- */

int tp_divide_by_zero(int a, int b, int c) {
    return a / (b - c); /* finding: divisor may be 0 */
}

int tn_divide_constant(int a) {
    return a / 100; /* no_finding: non-zero constant */
}

float tn_divide_float(void) {
    return 1.0f / 0.0f; /* no_finding: float division is IEEE-defined, not CWE-369 */
}

/* ---- unchecked-return (CWE-252) ---- */

int tp_unchecked_malloc(void) {
    int *p = (int *)malloc(sizeof(int) * 10);
    int r = p[0];
    free(p);
    return r; /* finding: p not checked for NULL */
}

int tn_checked_malloc(void) {
    int *p = (int *)malloc(sizeof(int) * 10);
    if (p == NULL) {
        return -1;
    }
    int r = p[0];
    free(p);
    return r; /* no_finding: p checked */
}

/* ---- path-traversal (CWE-22) ---- */

void tp_path_traversal(const char *path) {
    FILE *f = fopen(path, "r"); /* finding: non-literal path */
    if (f) {
        fclose(f);
    }
}

void tn_path_literal(void) {
    FILE *f = fopen("/etc/config", "r"); /* no_finding: literal path */
    if (f) {
        fclose(f);
    }
}

/* ---- sizeof-misuse (CWE-467/468) ---- */

void tp_sizeof_pointer(int n) {
    char **p = malloc(n * sizeof(p)); /* finding: sizeof pointer var */
    free(p);
}

void tn_sizeof_deref(void) {
    int *p = malloc(10 * sizeof(*p)); /* no_finding: sizeof *p is the element size, not sizeof-misuse */
    if (!p) {
        return;
    }
    free(p);
}

/* ---- signed-compare (CWE-681/195) ---- */

int tp_signed_compare(size_t len) {
    if (len < 0) { /* finding: unsigned always-false */
        return 1;
    }
    return 0;
}

int tn_signed_ok(int x) {
    if (x < 0) { /* no_finding: x is signed */
        return 1;
    }
    return 0;
}
