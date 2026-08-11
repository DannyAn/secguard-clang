/*
 * TC05 - Memory Leak: No Free (REQ-TC-005)
 * Vulnerability: memory allocated via malloc is never freed on any path.
 * Expected: MEMORY_RELEASE event absent; finding produced (memory leak)
 */

#include <stdlib.h>

int tc05_memleak_no_free(int n) {
    int *arr = (int *)malloc(sizeof(int) * n);
    if (!arr) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        arr[i] = i * 2;
    }
    return arr[0];
}