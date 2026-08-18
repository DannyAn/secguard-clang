#include <pthread.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static int g;

/* The mutex is acquired only on one branch, but the write to g sits textually
   between the lock and unlock lines. A line-range lockset wrongly treats g as
   protected; the CFG must-hold analysis sees the lock is conditional, so the
   write is unprotected on the other branch and races. */
void *tc58_worker(void *arg) {
    if (arg) {
        pthread_mutex_lock(&m);
    }
    g = 1;
    if (arg) {
        pthread_mutex_unlock(&m);
    }
    return 0;
}

void tc58_main(void) {
    pthread_t a, b;
    pthread_create(&a, 0, tc58_worker, 0);
    pthread_create(&b, 0, tc58_worker, 0);
}
