/*
 * TC03 - Checked Pointer (REQ-TC-003)
 * Safe pattern: pointer is guarded by NULL check before dereference.
 * Expected: NO finding (REQ-TDD-005)
 */

#include <stdlib.h>

typedef struct Item {
    int value;
} Item;

static Item *get_item(int id) {
    if (id < 0) {
        return NULL;
    }
    Item *it = (Item *)malloc(sizeof(Item));
    if (!it) {
        return NULL;
    }
    it->value = id;
    return it;
}

int tc03_checked_pointer(int id) {
    Item *it = get_item(id);
    if (it == NULL) {
        return -1;
    }
    int v = it->value;
    free(it);
    return v;
}