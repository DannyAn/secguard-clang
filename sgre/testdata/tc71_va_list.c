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
