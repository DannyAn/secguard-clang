/* tc121_interproc_cast_arg.c — NE-09 regression: a caller passing a
 * cast-wrapped or field-read nullable variable into an unguarded callee must
 * still synthesize the caller-side DEREFERENCE. */
#include <stdlib.h>

typedef struct { int x; } msg_t;
typedef struct { msg_t *slot; } holder_t;

static void send_msg(msg_t *m) {
    m->x = 1;
}

int caller_cast(void) {
    msg_t *m = (msg_t *)malloc(sizeof(msg_t));
    send_msg((msg_t *)m);
    return 0;
}

int caller_field(holder_t *h) {
    h->slot = (msg_t *)malloc(sizeof(msg_t));
    send_msg(h->slot);
    return 0;
}