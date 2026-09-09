#include "shared.h"
#include <pthread.h>

static void *worker(void *arg) {
    shared_counter++;
    return 0;
}

static void *worker2(void *arg) {
    shared_counter++;
    return 0;
}

void run(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, &worker, 0);
    pthread_create(&t2, 0, &worker2, 0);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
}
