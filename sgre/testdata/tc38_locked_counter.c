#include <pthread.h>

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_counter = 0;

void *thread_inc(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_mutex);
    g_counter++;
    pthread_mutex_unlock(&g_mutex);
    return NULL;
}

void spawn_threads(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_inc, NULL);
    pthread_create(&t2, NULL, thread_inc, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}
