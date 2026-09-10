#include "vsys.h"

extern void *g_buf;

uint32_t get_node(node_t **out)
{
    *out = (node_t *)g_buf;
    return 1;
}
