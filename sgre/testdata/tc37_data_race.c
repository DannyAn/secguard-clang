#include <pthread.h>

static int g_counter = 0;

void *thread_inc(void *arg) {
    (void)arg;
    g_counter++;
    return NULL;
}

void spawn_threads(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_inc, NULL);
    pthread_create(&t2, NULL, thread_inc, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}
