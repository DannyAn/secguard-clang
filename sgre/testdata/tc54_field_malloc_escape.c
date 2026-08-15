#include <stdlib.h>

typedef struct { char *in; char *out; } stream;

/* state->in = malloc(...) where state is a parameter: the field escapes into
 * the struct (owned by the caller), so it is not a leak of `state`. */
int fill_stream(stream *state) {
    state->in = (char *)malloc(64);
    state->out = (char *)malloc(64);
    if (state->in == NULL || state->out == NULL)
        return -1;
    return 0;
}

/* A local struct field malloc'd but never freed IS a leak. */
int local_field_leak(void) {
    stream local;
    local.in = (char *)malloc(64);
    if (local.in == NULL)
        return -1;
    return 0; /* local.in leaked */
}
