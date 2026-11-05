#include <stddef.h>

struct Session {
    int state;
};

static struct Session *g_session = NULL;

int get_session_state_safe(void)
{
    struct Session *session = g_session;

    if (session == NULL) {
        return -1;
    }

    return session->state;
}
