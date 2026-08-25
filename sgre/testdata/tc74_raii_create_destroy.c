#include <stdlib.h>

static int *g_items[8];
static int g_nitems;

// item_new's malloc is stored to a global on a LATER line than the allocation,
// so the detector's escape analysis does not connect it and would call it a
// leak. The item_free counterpart (which frees) marks item_new as RAII, so the
// would-be leak is suppressed.
void item_new(void) {
    int *p = (int *)malloc(64);
    g_items[g_nitems++] = p;
}

void item_free(void) {
    if (g_nitems > 0) {
        free(g_items[--g_nitems]);
    }
}
