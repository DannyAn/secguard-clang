#include <string.h>
#include <stdio.h>

void secure_lying_memcpy(char *src) {
    char dst[8];
    memcpy_s(dst, 100, src, 50); /* BUFFER_OVERFLOW: size 100 > capacity 8 */
}

void secure_lying_strcpy(char *src) {
    char dst[8];
    strcpy_s(dst, 64, src); /* BUFFER_OVERFLOW: size 64 > capacity 8 */
}

void secure_lying_sprintf(char *src) {
    char dst[8];
    sprintf_s(dst, 64, "%s", src); /* BUFFER_OVERFLOW: size 64 > capacity 8 */
}

void secure_var_size(char *src, size_t sz) {
    char dst[8];
    memcpy_s(dst, sz, src, 8); /* possible: sz caller-controlled, may exceed 8 */
}

void secure_correct(char *src) {
    char dst[8];
    memcpy_s(dst, sizeof(dst), src, 8); /* safe: sizeof(dst) == 8 */
}

void secure_constraint_memcpy(char *src) {
    char dst[16];
    memcpy_s(dst, 16, src, 64); /* constraint violation: count 64 > capacity 16 */
}

void secure_constraint_strcpy(void) {
    char dst[4];
    strcpy_s(dst, 4, "hello"); /* constraint violation: strlen("hello")+1 = 6 > 4 */
}
