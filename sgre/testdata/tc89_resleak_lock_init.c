/*
 * TC89 - Resource Leak: rwlock init not destroyed on malloc-fail return.
 * Vulnerability: pthread_rwlock_init acquires a lock resource; the malloc-fail
 *                branch returns without pthread_rwlock_destroy.
 * Expected: RESOURCE_ACQUIRE present (g_client_registry_lock),
 *           RESOURCE_RELEASE absent (lock leak).
 */

#include <stdlib.h>

typedef int pthread_rwlock_t;

static int pthread_rwlock_init(pthread_rwlock_t *lock, const void *attr) {
    (void)lock;
    (void)attr;
    return 0;
}

static int pthread_rwlock_destroy(pthread_rwlock_t *lock) {
    (void)lock;
    return 0;
}

static void *https_malloc(size_t n) {
    (void)n;
    return 0;
}

static pthread_rwlock_t g_client_registry_lock;
static void **g_https_client_record;
static int g_https_client_count;

void tc89_resleak_lock_init(void) {
    pthread_rwlock_init(&g_client_registry_lock, 0);
    g_https_client_record = (void **)https_malloc(sizeof(void *) * 8);
    if (g_https_client_record == 0) {
        return;
    }
    g_https_client_count = 0;
}
