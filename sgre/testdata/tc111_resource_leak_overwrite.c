/* tc111: overwritten resource handle (lost fd) must still be reported. */
#include <fcntl.h>
#include <unistd.h>

/* Both handles lost: fd is reassigned without closing the first. */
void overwrite_no_close(void) {
    int fd = open("/tmp/a", O_RDONLY);
    fd = open("/tmp/b", O_RDONLY);
}

/* First handle lost, second closed: one leak, not zero. */
void overwrite_then_close(void) {
    int fd = open("/tmp/a", O_RDONLY);
    fd = open("/tmp/b", O_RDONLY);
    close(fd);
}
