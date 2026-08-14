/*
 * Null-deref FP suppression: sizeof pseudo-deref (CWE-476)
 *
 * sizeof(p->field) and sizeof(p[0]) are compile-time type expressions, not
 * runtime pointer dereferences, so a possibly-NULL pointer operand can never
 * crash. The sizeof_pseudo_deref filter must suppress the null-deref finding.
 */

#include <stdlib.h>

typedef struct Node {
    int value;
} Node;

int nd_sizeof_pseudo_deref(void) {
    Node *node = (Node *)malloc(sizeof(Node)); /* nullable source: malloc may return NULL */
    int a = sizeof(node->value);               /* member-access pseudo-deref */
    int b = sizeof(node[0]);                   /* subscript pseudo-deref */
    free(node);
    return a + b;
}
