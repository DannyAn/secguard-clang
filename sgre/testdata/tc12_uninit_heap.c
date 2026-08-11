/*
 * TC12 - Uninit: Heap Malloc Use Without Write (REQ-TC-012)
 * Vulnerability: malloc'd memory is read before being written.
 * Expected: finding produced (uninitialized heap read)
 */

#include <stdlib.h>

int tc12_uninit_heap(void) {
    int *p = (int *)malloc(sizeof(int));
    if (!p) {
        return -1;
    }
    int v = *p;
    free(p);
    return v;
}