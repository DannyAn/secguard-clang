#include <stdlib.h>

typedef struct {
    char *msg;
    int mode;
} State;

/* frees only the msg field of *s (a field free, not a whole-struct free) */
void clear_msg(State *s) {
    free(s->msg);
    s->msg = NULL;
}

/* uses a DIFFERENT field after clear_msg freed s->msg: not a use-after-free.
 * Freeing s->msg dangles only s->msg, not s or s->mode. */
int use_mode_after_msg_free(State *s) {
    clear_msg(s);
    return s->mode;
}

/* whole-variable free then field use: a genuine use-after-free. */
int use_after_whole_free(void) {
    State *p = (State *)malloc(sizeof(State));
    free(p);
    return p->mode;
}
