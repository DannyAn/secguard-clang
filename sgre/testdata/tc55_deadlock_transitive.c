#include <pthread.h>

static pthread_mutex_t g_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_b = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_c = PTHREAD_MUTEX_INITIALIZER;

/* A transitive lock-order cycle A->B, B->C, C->A: no single 2-cycle exists,
   but the three threads together deadlock. */
void *tc55_thread_1(void *arg) {
    pthread_mutex_lock(&g_a);
    pthread_mutex_lock(&g_b);
    pthread_mutex_unlock(&g_b);
    pthread_mutex_unlock(&g_a);
    return 0;
}

void *tc55_thread_2(void *arg) {
    pthread_mutex_lock(&g_b);
    pthread_mutex_lock(&g_c);
    pthread_mutex_unlock(&g_c);
    pthread_mutex_unlock(&g_b);
    return 0;
}

void *tc55_thread_3(void *arg) {
    pthread_mutex_lock(&g_c);
    pthread_mutex_lock(&g_a);
    pthread_mutex_unlock(&g_a);
    pthread_mutex_unlock(&g_c);
    return 0;
}
