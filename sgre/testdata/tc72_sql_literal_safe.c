#include <sqlite3.h>
#include <stdio.h>

void literal_sql_safe(sqlite3 *db) {
    sqlite3_exec(db, "SELECT * FROM users", NULL, NULL, NULL); /* constant SQL: no event */
}

void placeholder_sql_safe(sqlite3 *db) {
    sqlite3_exec(db, "SELECT * FROM users WHERE id = ?", NULL, NULL, NULL); /* parameterized: no event */
}

void constant_copy_safe(char *buf) {
    sprintf(buf, "SELECT * FROM users"); /* no format specifier: no event */
}

void variable_sql_unsafe(sqlite3 *db, const char *q) {
    sqlite3_exec(db, q, NULL, NULL, NULL); /* variable SQL: INJECTION event */
}

void sprintf_sql_unsafe(sqlite3 *db, const char *name, char *buf) {
    sprintf(buf, "SELECT * FROM users WHERE name = '%s'", name); /* interpolated SQL: INJECTION event */
    sqlite3_exec(db, buf, NULL, NULL, NULL); /* variable SQL: INJECTION event */
}
