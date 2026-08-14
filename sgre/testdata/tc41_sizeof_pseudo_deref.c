/*
 * TC41 - sizeof pseudo-deref (CWE-476 false positive)
 *
 * sizeof(*p), sizeof(p->field), and sizeof(p[0]) are compile-time type
 * expressions, not runtime pointer dereferences. Even when the operand is a
 * possibly-NULL pointer, the compiler evaluates only its type, so the expression
 * can never crash at runtime.
 *
 * Expected: the DEREFERENCE events are still emitted (so interprocedural null
 * propagation keeps seeing them) but tagged is_type_expr=true, and the
 * null-deref chain drops them via the sizeof_pseudo_deref filter — zero
 * null-deref findings.
 */

#include <stdlib.h>

typedef struct Node {
    int value;
    struct Node *next;
} Node;

int tc41_sizeof_pseudo_deref(void) {
    Node *node = (Node *)malloc(sizeof(Node)); /* nullable source: malloc may return NULL */
    int a = sizeof(*node);                     /* type expr — not a runtime deref */
    int b = sizeof(node->value);               /* type expr — not a runtime deref */
    int c = sizeof(node[0]);                   /* type expr — not a runtime deref */
    return a + b + c;
}
