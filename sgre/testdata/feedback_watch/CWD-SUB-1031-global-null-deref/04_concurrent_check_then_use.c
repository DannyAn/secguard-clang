#include <pthread.h>
#include <stddef.h>

struct Session {
    int state;
};

static struct Session *g_session;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void *clear_session(void *arg)
{
    (void)arg;

    pthread_mutex_lock(&g_lock);
    g_session = NULL;
    pthread_mutex_unlock(&g_lock);

    return NULL;
}

int read_session_state(void)
{
    struct Session *session;

    pthread_mutex_lock(&g_lock);
    session = g_session;
    pthread_mutex_unlock(&g_lock);

    if (session == NULL) {
        return -1;
    }

    return session->state;
}
