#include <stdlib.h>

typedef struct { int *first; int *last; } block_list;

/* A memory allocator: its name contains "lock" inside "datablock", but it is
 * NOT a lock/resource acquirer and must not be flagged as one. */
static int *allocate_new_datablock(void) {
    return (int *)malloc(16);
}

int use_datablock(block_list *ll) {
    ll->first = ll->last = allocate_new_datablock();
    if (ll->first == NULL)
        return -1;
    return 0;
}

/* block_init contains "lock" inside "block"; it is a block helper, not a lock
 * acquirer, so &zip->first / &zip->last must not be flagged as lock acquires. */
static void block_init(int **first, int **last) {
    *first = 0;
    *last = 0;
}

int use_block_init(block_list *zip) {
    block_init(&zip->first, &zip->last);
    return 0;
}
