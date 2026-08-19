#include <string.h>
#include <stdlib.h>

void bounded_copy_overflow(void) {
    char dst[128];
    char src[256];
    strncpy(dst, src, 256); /* BUFFER_OVERFLOW: copy size 256 > dst capacity 128 */
}

void safe_bounded_copy(void) {
    char dst[256];
    char src[256];
    strncpy(dst, src, 128); /* safe: copy size 128 <= dst capacity 256 */
}

void bounded_copy_var_size(char *dst, char *src, int n) {
    strncpy(dst, src, n); /* safe: variable size, cannot prove overflow */
}