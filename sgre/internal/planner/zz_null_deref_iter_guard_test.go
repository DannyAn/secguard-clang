//go:build !nosqlite

package planner

import "testing"

// A macro-defined for-loop writes its iterator in the init clause and null-checks
// it in the condition (`(iter) != NULL` or a truthiness test `(iter)`), so the
// iterator is non-null on every path that reaches the body. A variable that is
// NULL-seeded before the macro must NOT be reported as a null-deref at its use
// inside the body. Reduced to generic shapes (the vendor-specific macros that
// surfaced the false positive are intentionally not reproduced).

const iterGuardPreamble = `#include <stdlib.h>

typedef struct node { int value; struct node *next; } node_t;
typedef struct sect { int id; } sect_t;

node_t *first_node(void *list) { return (node_t *)0; }
node_t *next_node(node_t *n) { return (node_t *)0; }
sect_t *first_sect(void *g) { return (sect_t *)0; }
sect_t *next_sect(void *g, sect_t *s) { return (sect_t *)0; }

#define FOR_EACH_NODE(head, iter, type) \
    for ((iter) = (type)first_node((head)); (iter) != NULL; \
         (iter) = (type)next_node((iter)))

#define FOR_EACH_SECT(group, sect) \
    for ((sect) = first_sect(group); (sect); (sect) = next_sect((group), (sect)))
`

func TestNullDeref_IteratorGuardNotNull(t *testing.T) {
	src := iterGuardPreamble + `
int scan_nodes(void *list) {
    node_t *pNode = NULL;
    FOR_EACH_NODE(list, pNode, node_t *)
    {
        if (1 == pNode->value) {
            return 0;
        }
    }
    return 1;
}

int scan_sects(void *g) {
    sect_t *sect = NULL;
    FOR_EACH_SECT(g, sect)
    {
        sect->id = 1;
    }
    return 0;
}
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "scan_nodes"); c != nil {
		t.Errorf("scan_nodes should NOT be flagged (iterator is null-checked by the loop condition), got var=%s", c.Target.Variable)
	}
	if c := candidateForFunc(t, result, "scan_sects"); c != nil {
		t.Errorf("scan_sects should NOT be flagged (iterator is truthiness-checked by the loop condition), got var=%s", c.Target.Variable)
	}
}
