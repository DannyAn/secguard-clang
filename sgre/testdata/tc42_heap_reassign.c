#include <stdlib.h>

typedef struct Node { int value; } Node;

static Node g_fallback;

/* q = &g_fallback after malloc redirects q away from the heap block, so
 * reading q->value is NOT a heap-uninit defect. */
int HeapReassign(int flag) {
    Node *q = (Node *)malloc(sizeof(Node));
    q = &g_fallback;
    return q->value;
}

/* Control: a genuine heap-uninit (malloc'd, never written through, then read)
 * must still be reported. */
int HeapUninitGenuine(void) {
    Node *r = (Node *)malloc(sizeof(Node));
    return r->value;
}
