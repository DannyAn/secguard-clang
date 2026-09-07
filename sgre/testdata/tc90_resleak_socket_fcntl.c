/*
 * TC90 - Resource Leak: socket not closed on fcntl-fail return.
 * Vulnerability: HPS_Socket acquires a socket; the HPS_Fcntl SETFL failure
 *                branch returns without HPS_Close.
 * Expected: RESOURCE_ACQUIRE present (socket_id),
 *           RESOURCE_RELEASE absent (socket leak on the error path).
 */

typedef unsigned int uint32_t;

static int HPS_Socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    return -1;
}

static int HPS_Fcntl(int fd, int cmd, int arg) {
    (void)fd;
    (void)cmd;
    (void)arg;
    return -1;
}

static int HPS_Close(int fd) {
    (void)fd;
    return 0;
}

uint32_t tc90_resleak_socket_fcntl(void) {
    int socket_id = HPS_Socket(2, 1 | 0x800, 0);
    if (socket_id <= 0) {
        return 1;
    }
    int flag = HPS_Fcntl(socket_id, 3, 0);
    if (HPS_Fcntl(socket_id, 4, flag | 0x800) < 0) {
        return 1;
    }
    HPS_Close(socket_id);
    return 0;
}
