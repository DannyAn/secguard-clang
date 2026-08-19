#include <string.h>

void var_size_overflow(char *src, size_t n) {
    char dst[16];
    strncpy(dst, src, n); /* BUFFER_OVERFLOW: n is caller-controlled, may exceed 16 */
}

void var_size_local(char *src) {
    char dst[16];
    size_t n = 8;
    strncpy(dst, src, n); /* safe: n is a bounded local */
}
