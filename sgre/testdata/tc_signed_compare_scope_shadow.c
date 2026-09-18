#include <stdlib.h>

static void *g_exceptions[64];
static unsigned g_exception_num;

int cmp_lookup_exception(unsigned index, const char *vsys, const char *module)
{
    for (unsigned i = index; i < g_exception_num; i++) {
    }
    return -1;
}

void cmp_clear_exception(const char *vsys, const char *module)
{
    /* 删掉"节点" */
    for (int i = cmp_lookup_exception(0, vsys, module);
         i >= 0; i = cmp_lookup_exception(i + 1, vsys, module)) {
        free(g_exceptions[i]);
        g_exceptions[i] = NULL;
    }


    unsigned count = 0;
    for (unsigned i = 0; i < g_exception_num; i++) {
        if (g_exceptions[i]) {
            g_exceptions[count] = g_exceptions[i];
            count++;
        }
    }
    g_exception_num = count;
}