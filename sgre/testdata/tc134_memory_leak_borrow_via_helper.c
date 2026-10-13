/*
 * TC134 - Memory Leak: get-or-create-and-cache BORROW via a HELPER call
 *
 * nlog_db_create_new_ctrl_item allocates, registers the pointer into a global
 * list through nlog_set_mon_disk_head (a helper that stores its argument to a
 * global), and returns the cached pointer. The caller must NOT free it, so
 * `entry *e = nlog_db_create_new_ctrl_item()` is not a leak. This is the
 * production pattern (nlog_db_create_new_ctrl_item / nlog_set_mon_disk_head)
 * that produced a high-severity false positive before the helper-call
 * ownership-transfer summary landed.
 */
#include <stdlib.h>

typedef struct entry { int v; } entry;

static entry *g_mon_disk_head;

void nlog_set_mon_disk_head(entry *e) {
    g_mon_disk_head = e;
}

entry *nlog_db_create_new_ctrl_item(void) {
    entry *e = malloc(sizeof(*e));
    nlog_set_mon_disk_head(e);
    return e;
}

int nlog_db_delete_all_table(void) {
    entry *e = nlog_db_create_new_ctrl_item();
    if (!e) {
        return -1;
    }
    e->v = 1;
    return 0;
}
