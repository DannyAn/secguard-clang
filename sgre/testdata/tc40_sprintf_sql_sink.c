#include <sqlite3.h>

void lookup_user_unsafe(sqlite3 *db, const char *username) {
    char query[512];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", username);
    sqlite3_exec(db, query, NULL, NULL, NULL);
}
