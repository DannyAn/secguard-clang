/*
 * TC149 - Memory Leak: asprintf failure guard on the direct call form.
 * `if (asprintf(&p, ...) < 0) return;` — the out-param allocation exists
 * only on the success branch; the failure early-return must not be leak
 * evidence (the allocation never happened there). The success path frees
 * p, so no leak is reported (docs §5.3: bind the allocation to success).
 */

#include <stdio.h>
#include <stdlib.h>

int tc149_asprintf_fail_guard(const char *name) {
    char *p = NULL;
    if (asprintf(&p, "hello %s", name) < 0) {
        return -1;
    }
    printf("%s\n", p);
    free(p);
    return 0;
}