/*
 * TC132 - Memory Leak: get-or-create-and-cache returns a BORROW, not ownership
 * get_item lazily allocates, caches into a global, and returns the cached
 * pointer. The caller must NOT free it, so `item *x = get_item(k)` is not a
 * leak. This is the nlog stat-registry accessor pattern (nlog_db_get_ctrl_item,
 * nlog_get_ai_detect_stat_list, ...) that produced confirmed false positives.
 */
#include <stdlib.h>

typedef struct item { int v; } item;

static item *g_cache[8];

item *get_item(int k) {
    item *p = g_cache[k];
    if (p) {
        return p;
    }
    p = malloc(sizeof(*p));
    g_cache[k] = p;
    return p;
}

int tc132_get_or_create(int k) {
    item *x = get_item(k);
    if (!x) {
        return -1;
    }
    x->v = 1;
    return 0;
}
