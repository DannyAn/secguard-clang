/*
 * TC150 - Memory Leak: asprintf failure guard on the assigned-status form.
 * `ret = asprintf(&p, ...); if (ret < 0) return;` — same success-branch
 * binding as TC149 but through a status variable, the equally common
 * enterprise form. The failure early-return must not be leak evidence.
 */

#include <stdio.h>
#include <stdlib.h>

int tc150_asprintf_assign_guard(const char *name) {
    char *p = NULL;
    int ret = asprintf(&p, "hello %s", name);
    if (ret < 0) {
        return -1;
    }
    printf("%s\n", p);
    free(p);
    return 0;
}