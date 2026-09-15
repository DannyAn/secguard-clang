#include <stdlib.h>

/* C1: an error path returns the pointer itself (`if (err) return p;`) while the
 * normal path never frees it. A function-level "is returned" flag suppresses the
 * leak on the non-returning path; the path-sensitive analysis must report it
 * (alloc without release). */
char *error_return_path(int err) {
    char *p = (char *)malloc(64);
    if (err) return p;
    p[0] = 'x';
    return 0;
}

/* Ownership transfer on every path (the malloc-failure NULL path carries no
 * allocation): NOT a leak. */
char *transfer_all_paths(int n) {
    char *p = (char *)malloc(n);
    if (!p) return 0;
    return p;
}
