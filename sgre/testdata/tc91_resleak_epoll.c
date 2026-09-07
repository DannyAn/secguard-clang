/*
 * TC91 - Resource Leak: epoll fd not closed on db-connect-fail return.
 * Vulnerability: MESH_EpollCreate acquires an epoll fd; the
 *                db_create_sub_connect failure branch returns without
 *                MESH_Close.
 * Expected: RESOURCE_ACQUIRE present (g_drop_mon_epoll_fd),
 *           RESOURCE_RELEASE absent (fd leak on the error path).
 *           db_create_sub_connect returns an error code, so `ret` must NOT
 *           be flagged as an acquired resource.
 */

static int MESH_EpollCreate(void) {
    return -1;
}

static int MESH_Close(int fd) {
    (void)fd;
    return 0;
}

static int db_create_sub_connect(void *attr, void *ctrl, void *out) {
    (void)attr;
    (void)ctrl;
    (void)out;
    return -1;
}

static int g_drop_mon_epoll_fd;
static int g_drop_mon_sub_conn;

int tc91_resleak_epoll(void) {
    g_drop_mon_epoll_fd = MESH_EpollCreate();
    if (g_drop_mon_epoll_fd < 0) {
        return -1;
    }
    int ret = db_create_sub_connect(0, 0, &g_drop_mon_sub_conn);
    if (ret != 0) {
        return -1;
    }
    MESH_Close(g_drop_mon_epoll_fd);
    return 0;
}
