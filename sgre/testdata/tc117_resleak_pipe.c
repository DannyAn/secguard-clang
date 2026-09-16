/* C5: pipe/socketpair write TWO fds into an out-param array (`pipe(fds)`).
 * The return value is an error code, not a handle; both fds[0] and fds[1] are
 * the acquired resources and each must be closed. */

void pipe_leak(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        return;
    }
    /* neither fds[0] nor fds[1] is closed -> two leaked fds */
}

void pipe_closed(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        return;
    }
    close(fds[0]);
    close(fds[1]);
}
