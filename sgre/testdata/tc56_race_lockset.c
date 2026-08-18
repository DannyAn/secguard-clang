#include <pthread.h>

static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t m2 = PTHREAD_MUTEX_INITIALIZER;
static int g;

/* The same thread body is created twice, and it writes the shared global g
   under TWO DIFFERENT mutexes (m1 then m2). No single mutex consistently
   protects g, so this is a data race even though each individual write is
   inside SOME lock scope. */
void *tc56_worker(void *arg) {
    pthread_mutex_lock(&m1);
    g = 1;
    pthread_mutex_unlock(&m1);

    pthread_mutex_lock(&m2);
    g = 2;
    pthread_mutex_unlock(&m2);
    return 0;
}

void tc56_main(void) {
    pthread_t a, b;
    pthread_create(&a, 0, tc56_worker, 0);
    pthread_create(&b, 0, tc56_worker, 0);
}
