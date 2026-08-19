#include <string.h>

void memcpy_const_overflow(char *src) {
    char dst[8];
    memcpy(dst, src, 16); /* BUFFER_OVERFLOW: 16 > 8 */
}

void memcpy_const_fit(char *src) {
    char dst[8];
    memcpy(dst, src, 8); /* safe: exact fit */
}

void memcpy_var_param(char *src, size_t n) {
    char dst[8];
    memcpy(dst, src, n); /* possible: n caller-controlled, may exceed 8 */
}

void memcpy_unknown_dst(char *dst, char *src, size_t n) {
    memcpy(dst, src, n); /* conservative: unknown capacity → generic buffer_overflow */
}

void strncat_append(char *src) {
    char dst[16] = "abc";
    strncat(dst, src, 8); /* append: n fits but existing content unknown → generic */
}
