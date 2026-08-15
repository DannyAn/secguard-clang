#include <stdlib.h>

typedef struct { char *out; char *in; int err; } State;

/* lookup frees s->out ONLY on the error path (which returns -1). The caller
 * resumes on the success path where s->out was NOT freed, so a caller that
 * checks the error before using s->out has no use-after-free. */
int lookup(State *s) {
    if (s->err) {
        free(s->out);
        return -1;
    }
    return 0;
}

int caller_checks_error(State *s) {
    if (lookup(s) < 0)
        return -1;
    return s->out[0];
}

/* Whole-variable free (unconditional) — a later field use IS a use-after-free. */
int caller_whole_free(void) {
    State *p = (State *)malloc(sizeof(State));
    free(p);
    return p->out ? 1 : 0; /* use p->out after free(p) */
}
