
#include <pthread.h>

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_counter = 0;


typedef struct {
    pthread_mutex_t *mutex;
} LockGuard;

LockGuard LockGuard_create(pthread_mutex_t *m) {
    LockGuard g;
    g.mutex = m;
    pthread_mutex_lock(m);  
    return g;
}

void LockGuard_release(LockGuard *g) {
    pthread_mutex_unlock(g->mutex);  
}


void increment_counter(void) {
    LockGuard guard = LockGuard_create(&g_mutex);

    g_counter++;
                  
    

    LockGuard_release(&guard);

    
}


static int g_unprotected = 0;

void increment_unprotected(void) {
    g_unprotected++;

    
}
