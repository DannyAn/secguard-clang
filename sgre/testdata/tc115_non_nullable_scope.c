#include <stdlib.h>

/* P5: a local array `buf` in array_scope must NOT mark the same-named POINTER
 * `buf` in pointer_scope as non-nullable. The file-scoped-by-name version
 * suppressed pointer_scope's malloc-unchecked null-deref (a silent FN). */
void array_scope(void) {
    char buf[16];
    buf[0] = 'x';
}

void pointer_scope(void) {
    char *buf = (char *)malloc(16);
    buf[0] = 'x';
    free(buf);
}
