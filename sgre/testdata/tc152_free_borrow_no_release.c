/*
 * TC152 - Memory Leak: borrowed return value is not an allocation.
 * strstr returns a pointer INTO the input string (possibly NULL): it is
 * neither a fresh allocation nor a caller-owned object. free(p) on it must
 * not be recorded as a valid release of a tracked allocation, and the
 * variable must not be reported as a leak (docs §5.4/§9.1).
 */

#include <string.h>
#include <stdlib.h>

void tc152_free_borrow_no_release(const char *hay, const char *needle) {
    char *p = strstr(hay, needle);
    if (p == NULL) return;
    free(p);
}