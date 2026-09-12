/* tc111: a free guarded by a positive check on the same pointer is a release,
 * not a leak (mirrors the resource-leak guarded-release shape). A free guarded
 * by an unrelated condition still leaks. */
#include <stdlib.h>

/* `if (p) { free(p); }` — the NULL path owns nothing, so this is a release. */
void guarded_free(void) {
    char *p = (char *)malloc(64);
    if (p) {
        free(p);
    }
}

/* `if (flag) { free(p); }` — flag != p, so the false path leaks the block. */
void conditional_free(int flag) {
    char *p = (char *)malloc(64);
    if (flag) {
        free(p);
    }
}
