#include <stdlib.h>

/* malloc inside an if-condition's short-circuit: the (path = malloc(n)) == NULL
 * branch returns early (a null guard), and the success path frees path — not a
 * leak. */
void *gzdopen_style(int fd) {
    char *path;
    if (fd == -1 || (path = (char *)malloc(64)) == NULL)
        return NULL;
    path[0] = 'x';
    free(path);
    return NULL;
}

/* A genuine leak: malloc then return 0 without freeing buf. */
int genuine_leak(void) {
    char *buf = (char *)malloc(64);
    if (buf == NULL)
        return -1;
    buf[0] = 'x';
    return 0;
}
