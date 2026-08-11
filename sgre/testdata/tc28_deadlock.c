#include <pthread.h>

static pthread_mutex_t g_mutex_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutex_b = PTHREAD_MUTEX_INITIALIZER;

void *tc28_thread_a(void *arg) {
    pthread_mutex_lock(&g_mutex_a);
    pthread_mutex_lock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_a);
    return 0;
}

void *tc28_thread_b(void *arg) {
    pthread_mutex_lock(&g_mutex_b);
    pthread_mutex_lock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_b);
    return 0;
}