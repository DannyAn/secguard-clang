#include <stddef.h>

struct Session {
    int state;
};

static struct Session *g_session;

static void initialize_session(struct Session *session)
{
    g_session = session;
}

static int consume_session(void)
{
    return g_session->state;
}

int run(struct Session *input)
{
    initialize_session(input);
    return consume_session();
}
