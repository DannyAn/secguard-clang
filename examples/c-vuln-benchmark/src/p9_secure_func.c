/*
 * P9 — Annex K `_s` 安全函数契约分析用例
 *
 * 锁定"安全函数"的误用检测（业界普遍把 _s 当无条件安全，SecGuard 按契约校验）：
 *   - 拷贝类：memcpy_s / strcpy_s 的容量参数说谎（大于真实缓冲区）→ 溢出
 *   - 约束违约：strcpy_s 源长超过声明容量 → constraint violation
 *   - scanf_s 逐转换宽度：宽度参数大于真实缓冲区 → 溢出
 */

#include <string.h>
#include <stdio.h>

/* 真阳性：memcpy_s 容量参数 100 > 真实容量 8（应报告 finding） */
void tp_secure_lying_size(char *src) {
    char dst[8];
    memcpy_s(dst, 100, src, 50);
}

/* 误报：容量参数 sizeof(dst) 如实反映缓冲区（应抑制） */
void fp_secure_correct(char *src) {
    char dst[8];
    memcpy_s(dst, sizeof(dst), src, 8);
}

/* 真阳性：strcpy_s 源长 6 > 声明容量 4，约束违约（应报告 finding） */
void tp_secure_constraint(void) {
    char dst[4];
    strcpy_s(dst, 4, "hello");
}

/* 真阳性：scanf_s 宽度参数 100 > 真实容量 10（应报告 finding） */
void tp_scanf_lying_size(void) {
    char buf[10];
    scanf_s("%s", buf, (rsize_t)100);
}

/* 误报：scanf_s 宽度参数 sizeof(buf) 如实反映缓冲区（应抑制） */
void fp_scanf_correct(void) {
    char buf[10];
    scanf_s("%s", buf, (rsize_t)sizeof(buf));
}

/* ── memcpy_s 完整签名（errno_t + restrict）──────────────────────── */

/* 真阳性：destsz 100 > 真实容量 8（说谎的 destsz，应报告 finding） */
errno_t tp_memcpy_s_lying_destsz(char *restrict src) {
    char dst[8];
    return memcpy_s(dst, 100, src, 50);
}

/* 误报：destsz=sizeof(dst)、count=8，如实且不越界（应抑制） */
errno_t fp_memcpy_s_correct(char *restrict src) {
    char dst[8];
    return memcpy_s(dst, sizeof(dst), src, 8);
}

/* 真阳性：destsz=sizeof(dst)=8 但 count=100 > destsz，约束违约（应报告 finding） */
errno_t tp_memcpy_s_count_overflow(char *restrict src) {
    char dst[8];
    return memcpy_s(dst, sizeof(dst), src, 100);
}
