#include <stdio.h>
#include <stdlib.h>

void test_sprintf_s_fp_const_format(void) {
    char buf[256];
    sprintf_s(buf, sizeof(buf), "Static format %d", 42);
}

void test_sprintf_s_fp_sql_safe(void *db) {
    char buf[256];
    sprintf_s(buf, sizeof(buf), "SELECT * FROM users WHERE id = %d", 42);
    sqlite3_exec(db, buf, NULL, NULL, NULL);
}

void test_sprintf_s_fp_no_crlf(char *user_input, FILE *data) {
    char buf[256];
    sprintf_s(buf, sizeof(buf), "%s\n", user_input);
    fprintf(data, "%s", buf);
}