#include <pthread.h>

static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t m2 = PTHREAD_MUTEX_INITIALIZER;
static int g_shared;

/* F8: the guard branch unlocks and returns early, but the write below is still
   inside the critical section on the surviving path — it must NOT be read as
   "shared state written after the lock is released". The guard-branch unlock is
   an early exit, not the critical section's end. */
void tc192_guard_unlock(int flag) {
    pthread_mutex_lock(&m1);
    if (flag) {
        pthread_mutex_unlock(&m1);
        return;
    }
    g_shared = 1;
    pthread_mutex_unlock(&m1);
}

/* Genuine TOCTOU-shared-state: the second write lands after the final unlock,
   so it is unprotected and must still be flagged. */
void tc192_after_unlock(void) {
    pthread_mutex_lock(&m2);
    g_shared = 2;
    pthread_mutex_unlock(&m2);
    g_shared = 3;
}
