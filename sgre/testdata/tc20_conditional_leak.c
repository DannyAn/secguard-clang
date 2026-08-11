#include <stdlib.h>

int test_conditional_leak(int flag) {
    char *buf = (char *)malloc(1024);
    if (flag) {
        return -1;
    }
    free(buf);
    return 0;
}