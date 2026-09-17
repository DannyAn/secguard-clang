#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void test_snprintf_s_fp_const_format(void) {
    char buf[256];
    snprintf_s(buf, sizeof(buf), "Static format %d", 42);
}

void test_snprintf_s_fp_sql_safe(void *db) {
    char buf[256];
    snprintf_s(buf, sizeof(buf), "SELECT * FROM users WHERE id = %d", 42);
    sqlite3_exec(db, buf, NULL, NULL, NULL);
}

void test_vsnprintf_s_fp_const_format(const char *fmt, va_list ap) {
    char buf[256];
    vsnprintf_s(buf, sizeof(buf), fmt, ap);
}
