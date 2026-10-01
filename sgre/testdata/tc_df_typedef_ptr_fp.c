#include <stdlib.h>

typedef struct node {
    int v;
} node_t;

typedef node_t *node_ptr_t;

void free_nodes(node_ptr_t n)
{
    free(n);
}

void caller_double_free(void)
{
    node_ptr_t a = malloc(sizeof(node_t));
    free_nodes(a);
    free_nodes(a);
}

void positive_control(void)
{
    char *p = malloc(100);
    free(p);
    free(p);
}
