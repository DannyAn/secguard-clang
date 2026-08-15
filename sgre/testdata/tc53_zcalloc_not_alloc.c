#include <stdlib.h>

typedef void *(*alloc_func)(void *, unsigned, unsigned);
typedef struct { alloc_func zalloc; void *opaque; } z_stream;

void *zcalloc(void *opaque, unsigned items, unsigned size) {
    (void)opaque;
    return calloc(items, size);
}

/* strm->zalloc = zcalloc assigns a function pointer; "zcalloc" contains
 * "calloc" but it is NOT an allocation and must not be reported as a leak. */
int init_stream(z_stream *strm) {
    strm->zalloc = zcalloc;
    strm->opaque = (void *)0;
    return 0;
}
