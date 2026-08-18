#include <pthread.h>

static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t m2 = PTHREAD_MUTEX_INITIALIZER;
static int g;

/* Two DIFFERENT thread functions, each created once, write the shared global g
   under different mutexes (m1 vs m2). No single mutex protects both, so this is
   a cross-function data race — the old per-function pass missed it because each
   function is created only once. */
void *tc57_thread_a(void *arg) {
    pthread_mutex_lock(&m1);
    g = 1;
    pthread_mutex_unlock(&m1);
    return 0;
}

void *tc57_thread_b(void *arg) {
    pthread_mutex_lock(&m2);
    g = 2;
    pthread_mutex_unlock(&m2);
    return 0;
}

void tc57_main(void) {
    pthread_t a, b;
    pthread_create(&a, 0, tc57_thread_a, 0);
    pthread_create(&b, 0, tc57_thread_b, 0);
}
