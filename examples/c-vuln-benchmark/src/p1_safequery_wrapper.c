
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>




typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt;
} SafeQuery;

SafeQuery *SafeQuery_prepare(sqlite3 *db, const char *sql) {
    SafeQuery *q = (SafeQuery *)malloc(sizeof(SafeQuery));
    q->db = db;
    sqlite3_prepare_v2(db, sql, -1, &q->stmt, NULL);
    return q;
}

void SafeQuery_bind_text(SafeQuery *q, int index, const char *value) {
    sqlite3_bind_text(q->stmt, index, value, -1, SQLITE_TRANSIENT);
}

int SafeQuery_exec(SafeQuery *q) {
    return sqlite3_step(q->stmt);
}

void SafeQuery_free(SafeQuery *q) {
    sqlite3_finalize(q->stmt);
    free(q);
}


void lookup_user(sqlite3 *db, const char *username) {
    
    SafeQuery *q = SafeQuery_prepare(db, "SELECT * FROM users WHERE name = ?");
    SafeQuery_bind_text(q, 1, username);
    SafeQuery_exec(q);

    
    SafeQuery_free(q);
}


void lookup_user_unsafe(sqlite3 *db, const char *username) {
    char query[512];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", username);
    sqlite3_exec(db, query, NULL, NULL, NULL);


}
