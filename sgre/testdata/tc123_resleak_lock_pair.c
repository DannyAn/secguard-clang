/*
 * TC123 - Resource Leak: lock/unlock wrapper pair must NOT be auto-confirmed.
 *
 * A mutex locked in one function and unlocked in a sibling function (a
 * `xxx_lock()` / `xxx_unlock()` wrapper pair) is a standard pairing, not a
 * leak. The detector cannot see the cross-function unlock, so the lock acquire
 * must stay suspected for the AI — never marked definite (auto-confirmed).
 */

typedef struct { int x; } pthread_mutex_t;
typedef struct { int x; } pthread_rwlock_t;

static int pthread_mutex_lock(pthread_mutex_t *m) { (void)m; return 0; }
static int pthread_mutex_unlock(pthread_mutex_t *m) { (void)m; return 0; }
static int pthread_rwlock_rdlock(pthread_rwlock_t *l) { (void)l; return 0; }
static int pthread_rwlock_unlock(pthread_rwlock_t *l) { (void)l; return 0; }

static pthread_mutex_t g_foo_mutex;
static pthread_rwlock_t g_bar_rwlock;

__attribute__((noinline)) void foo_lock(void) {
    (void)pthread_mutex_lock(&g_foo_mutex);
}

__attribute__((noinline)) void foo_unlock(void) {
    (void)pthread_mutex_unlock(&g_foo_mutex);
}

void bar_rdlock(void) {
    (void)pthread_rwlock_rdlock(&g_bar_rwlock);
}

void bar_unlock(void) {
    (void)pthread_rwlock_unlock(&g_bar_rwlock);
}
