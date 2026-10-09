/*
 * TC122 - Memory Leak: *_create functions are not heap malloc
 * Functions like db_create_sync_conn, pthread_create, cJSON_CreateObject
 * create resources/objects/threads, not heap blocks. They must not be
 * treated as malloc by the zero-config allocator heuristic, or every
 * assignment from them becomes a confirmed false-positive leak.
 */
#include <stdlib.h>

typedef struct conn { int fd; } conn;
conn *db_create_sync_conn(const char *host);
void db_close_sync_conn(conn *c);

int tc122_create_not_malloc(const char *host) {
    conn *c = db_create_sync_conn(host);
    if (!c) return -1;
    c->fd = 0;
    db_close_sync_conn(c);
    return 0;
}
