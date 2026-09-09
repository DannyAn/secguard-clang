#include <pthread.h>

static int g;

static void *worker(void *arg) {
    g++;
    return 0;
}

static void *worker2(void *arg) {
    g++;
    return 0;
}

void addr_taken_missed(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, &worker, 0);  /* gap: &worker not recognized as thread fn */
    pthread_create(&t2, 0, &worker2, 0);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
}
