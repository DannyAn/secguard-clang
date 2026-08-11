/*
 * TC04 - Interprocedural Propagation (REQ-TC-004)
 * Vulnerability: NULL value propagates through a 2-function call chain
 *                to a dereference.
 * Expected: finding produced (interprocedural null dereference)
 */

#include <stdlib.h>

typedef struct Handle {
    int fd;
} Handle;

static Handle *open_handle(const char *path) {
    if (!path) {
        return NULL;
    }
    Handle *h = (Handle *)malloc(sizeof(Handle));
    if (!h) {
        return NULL;
    }
    h->fd = -1;
    return h;
}

static int read_handle(Handle *h) {
    return h->fd;
}

int tc04_interprocedural(const char *path) {
    Handle *h = open_handle(path);
    return read_handle(h);
}