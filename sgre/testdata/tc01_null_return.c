/*
 * TC01 - Null Return (REQ-TC-001)
 * Vulnerability: get_node() returns NULL on failure; caller dereferences
 *                the result without a NULL check.
 * Expected: finding produced (null dereference)
 */

#include <stdlib.h>

typedef struct Node {
    int value;
    struct Node *next;
} Node;

static Node *get_node(int id) {
    if (id < 0) {
        return NULL;
    }
    Node *n = (Node *)malloc(sizeof(Node));
    if (!n) {
        return NULL;
    }
    n->value = id;
    n->next = NULL;
    return n;
}

int tc01_null_return(int id) {
    Node *node = get_node(id);
    return node->value;
}