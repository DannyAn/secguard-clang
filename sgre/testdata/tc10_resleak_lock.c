/*
 * TC10 - Resource Leak: Lock Without Unlock (REQ-TC-010)
 * Vulnerability: a lock is acquired but never released.
 * Expected: finding produced (lock resource leak)
 */

typedef struct {
    int locked;
} sg_mutex_t;

static void sg_lock(sg_mutex_t *m) {
    m->locked = 1;
}

static void sg_unlock(sg_mutex_t *m) {
    m->locked = 0;
}

static sg_mutex_t g_mutex = {0};

int tc10_resleak_lock(int *shared) {
    sg_lock(&g_mutex);
    int v = *shared;
    *shared = v + 1;
    return v;
}