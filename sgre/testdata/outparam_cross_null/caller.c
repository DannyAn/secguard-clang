#include "vsys.h"

void *g_buf;

void caller(void)
{
    node_t *n = NULL;
    get_node(&n);
    n->val = 1;
}

void real_null_deref(void)
{
    node_t *n = NULL;
    n->val = 1;
}
