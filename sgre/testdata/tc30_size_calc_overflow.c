#include <stdlib.h>

void tc30_size_calc_overflow(int count, int obj_size) {
    void *buf = malloc(count * obj_size);
    free(buf);
}
