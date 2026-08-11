#include <stdlib.h>

int test_uninit_flag() {
    int flag;
    if (flag == 1) {
        return 1;
    }
    return 0;
}