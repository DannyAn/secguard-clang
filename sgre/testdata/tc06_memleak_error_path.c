/*
 * TC06 - Memory Leak: Error Path Missing Free (REQ-TC-006)
 * Vulnerability: memory is freed on the success path but not on an
 *                early error-return path.
 * Expected: finding produced (memory leak on error path)
 */

#include <stdlib.h>

int tc06_memleak_error_path(int n, int fail) {
    int *buf = (int *)malloc(sizeof(int) * n);
    if (!buf) {
        return -1;
    }
    buf[0] = 42;

    if (fail) {
        return -2;
    }

    int result = buf[0];
    free(buf);
    return result;
}