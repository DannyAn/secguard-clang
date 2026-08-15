#include <stdlib.h>
#include <string.h>

/* strcpy of a short literal into a local fixed array: provably safe. */
void local_array_safe(void) {
    char dst[8];
    strcpy(dst, "hello");
    (void)dst;
}

/* strcat appends to existing content, so "literal fits in total capacity" does
 * not prove safety: it must still be flagged. */
void strcat_into_fresh_buffer(void) {
    char *dst = (char *)malloc(256);
    if (dst) {
        dst[0] = 0;
        strcat(dst, "hello");
    }
    free(dst);
}
