#include <stdlib.h>

void *tc23_ownership_transfer(int n) {
    char *buf = (char *)malloc(n);
    if (!buf) return 0;
    return buf;
}