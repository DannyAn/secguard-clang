/*
 * TC02 - Malloc Failure (REQ-TC-002)
 * Vulnerability: malloc result is used without a NULL check.
 * Expected: finding produced (null dereference via unchecked malloc)
 */

#include <stdlib.h>

typedef struct Buffer {
    int  size;
    char data[1];
} Buffer;

int tc02_malloc_failure(int n) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer) + n);
    buf->size = n;
    return buf->size;
}