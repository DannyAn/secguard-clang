#include <stdlib.h>

void test_off_by_one() {
    char buf[64];
    int i;
    for (i = 0; i <= 64; i++) {
        buf[i] = 0;
    }
}