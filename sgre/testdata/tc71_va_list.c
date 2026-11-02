#include <stdarg.h>
#include <stdio.h>

char g_va_buf[1024];

/* 标准用法：va_start 初始化 args；va_start 那一行的 args 参数是写目标，
   不是 read，必须不报 stack_uninit。 */
char *va_ok(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_va_buf, sizeof(g_va_buf), fmt, args);
    va_end(args);
    return g_va_buf;
}

/* 真 uninit：args 在 va_start 之前被 use，应报 stack_uninit。 */
char *va_use_before_start(const char *fmt, ...) {
    va_list args;
    vsnprintf(g_va_buf, sizeof(g_va_buf), fmt, args);
    va_start(args, fmt);
    va_end(args);
    return g_va_buf;
}

/* va_copy 初始化 copy：copy 必须不报 stack_uninit。 */
char *va_copy_ok(const char *fmt, ...) {
    va_list args, copy;
    va_start(args, fmt);
    va_copy(copy, args);
    vsnprintf(g_va_buf, sizeof(g_va_buf), fmt, copy);
    va_end(copy);
    va_end(args);
    return g_va_buf;
}

/* 两轮遍历：同一个 va_list 被 va_start 初始化两次。第一次 va_start 之后的
   va_arg/va_end（第二次 va_start 之前）也必须不报——第二次 va_start 不得把
   init line 覆盖到更后面。 */
int va_double_start(const char *first, ...) {
    va_list args;
    int n = 0;
    va_start(args, first);
    const char *a;
    while ((a = va_arg(args, const char *)) != NULL) { n++; }
    va_end(args);

    va_start(args, first);
    while ((a = va_arg(args, const char *)) != NULL) { n++; }
    va_end(args);
    return n;
}
