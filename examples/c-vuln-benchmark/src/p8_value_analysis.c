/*
 * P8 — 值分析 / 区间域（RangeAnalysis lite）用例
 *
 * 锁定变量界定的 CWE-190 溢出识别与守卫常量传播：
 *   - malloc(n * sizeof(T)) / malloc(n * m) / calloc(n, m)：变量乘积溢出
 *   - malloc(n + 1) / malloc(n * 4)：加法 / 乘常量溢出（n 为形参，caller 可控）
 *   - if (n < 100) 守卫后：守卫界收敛，加法溢出被抑制
 */

#include <stdlib.h>

/* 真阳性：n * sizeof(int) 乘积可溢出（应报告 finding） */
void tp_sizeof_product(int n) {
    char *p = malloc(n * sizeof(int));
    if (p) free(p);
}

/* 真阳性：n * m 双变量乘积可溢出（应报告 finding） */
void tp_two_var_product(int n, int m) {
    char *p = malloc(n * m);
    if (p) free(p);
}

/* 真阳性：calloc(n, m) 隐式乘积可溢出（应报告 finding） */
void tp_calloc_two_var(int n, int m) {
    char *p = calloc(n, m);
    if (p) free(p);
}

/* 真阳性：n + 1 加法可溢出，n 为形参（应报告 finding） */
void tp_param_add_const(size_t n) {
    char *p = malloc(n + 1);
    if (p) free(p);
}

/* 真阳性：n * 4 乘常量可溢出，n 为形参（应报告 finding） */
void tp_param_mul_const(size_t n) {
    char *p = malloc(n * 4);
    if (p) free(p);
}

/* 误报：if (n < 100) 守卫后 n + 1 不可能溢出（应抑制） */
void fp_guard_add(size_t n) {
    if (n < 100) {
        char *p = malloc(n + 1);
        if (p) free(p);
    }
}
