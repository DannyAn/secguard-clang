#include <stdlib.h>

typedef struct node {
    int value;
} node_t;

typedef struct list {
    node_t *head;
} list_t;

void list_add(list_t *list, node_t *node);

void f(void)
{
    node_t *node = (node_t *)malloc(sizeof(node_t));
    list_t list;
    list_add(&list, node);
}
