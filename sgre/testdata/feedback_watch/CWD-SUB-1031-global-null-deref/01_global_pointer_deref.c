#include <stddef.h>

struct Session {
    int state;
};

static struct Session *g_session = NULL;

int get_session_state(void)
{
    return g_session->state;
}

int main(void)
{
    return get_session_state();
}
