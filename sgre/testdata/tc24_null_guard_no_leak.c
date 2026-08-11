#include <stdlib.h>

void tc23_null_guard_no_leak(int n) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    buf[0] = 'x';
    free(buf);
}