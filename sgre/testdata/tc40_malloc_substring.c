#include <stdlib.h>

/* A wrapper whose NAME and a string literal both spell "malloc" must not be
 * mistaken for an actual malloc() return — the null-source detector matches the
 * callee, not a "malloc" substring in the statement text. */
static char *pre_malloc_log(const char *msg) {
    return (char *)msg;
}

int uses_wrapper(void) {
    char *p = pre_malloc_log("called malloc");
    return p != 0;
}
