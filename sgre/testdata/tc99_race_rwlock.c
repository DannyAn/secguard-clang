#include <pthread.h>

static int g;
static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;

static void *worker(void *arg) {
    pthread_rwlock_wrlock(&rw);
    g++;
    pthread_rwlock_unlock(&rw);
    return 0;
}

static void *worker2(void *arg) {
    pthread_rwlock_wrlock(&rw);
    g++;
    pthread_rwlock_unlock(&rw);
    return 0;
}

void run(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, &worker, 0);
    pthread_create(&t2, 0, &worker2, 0);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
}
