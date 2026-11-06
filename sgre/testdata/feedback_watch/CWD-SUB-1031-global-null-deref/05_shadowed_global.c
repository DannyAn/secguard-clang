struct session {
    int flags;
};

static struct session *g_session = 0;

extern struct session *acquire_session(void);

int read_shadowed(int ready)
{
    struct session *g_session = acquire_session();
    if (!ready || g_session == 0) {
        return 0;
    }
    return g_session->flags;
}
