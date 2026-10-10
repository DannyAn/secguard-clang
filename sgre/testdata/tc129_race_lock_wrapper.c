/*
 * TC129 - Data race: a shared global written between a pure lock/unlock WRAPPER
 * pair (`foo_lock()` / `foo_unlock()` wrapping pthread_mutex_lock/unlock) is
 * protected, not a race. The detector must recognize the wrapper pair and treat
 * it exactly like the direct primitives (P1-4).
 */

#include <pthread.h>

static pthread_mutex_t g_foo_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_shared;

__attribute__((noinline)) void foo_lock(void) {
    (void)pthread_mutex_lock(&g_foo_mutex);
}

__attribute__((noinline)) void foo_unlock(void) {
    (void)pthread_mutex_unlock(&g_foo_mutex);
}

void *tc129_worker(void *arg) {
    foo_lock();
    g_shared = 1; /* protected by the foo_lock / foo_unlock wrapper pair */
    foo_unlock();
    return 0;
}

void tc129_main(void) {
    pthread_t a, b;
    pthread_create(&a, 0, tc129_worker, 0);
    pthread_create(&b, 0, tc129_worker, 0);
}
