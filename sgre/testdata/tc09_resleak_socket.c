/*
 * TC09 - Resource Leak: Socket Without Close (REQ-TC-009)
 * Vulnerability: a socket is opened but never closed.
 * Expected: finding produced (socket resource leak)
 */

typedef unsigned int socklen_t;

static int sg_socket(int domain, int type, int protocol) {
    return -1;
}

static int sg_bind(int fd, void *addr, socklen_t len) {
    return 0;
}

int tc09_resleak_socket(void *addr, socklen_t len) {
    int fd = sg_socket(2, 1, 0);
    if (fd < 0) {
        return -1;
    }
    sg_bind(fd, addr, len);
    return fd;
}