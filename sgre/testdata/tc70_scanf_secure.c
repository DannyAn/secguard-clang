#include <stdio.h>

void scanf_lying_size(void) {
    char buf[10];
    scanf_s("%s", buf, (rsize_t)100); /* BUFFER_OVERFLOW: size 100 > capacity 10 */
}

void scanf_correct(void) {
    char buf[10];
    scanf_s("%s", buf, (rsize_t)sizeof(buf)); /* safe: sizeof(buf) == 10 */
}

void scanf_var_size(rsize_t sz) {
    char buf[10];
    sscanf_s("input", "%s", buf, sz); /* possible: sz caller-controlled */
}

void scanf_mixed(void) {
    int x;
    char buf[8];
    sscanf_s("42 hello", "%d %s", &x, buf, (rsize_t)64); /* BUFFER_OVERFLOW: size 64 > 8 */
}
