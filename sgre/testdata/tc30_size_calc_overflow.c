#include <stdlib.h>

void tc30_size_calc_overflow(size_t count, size_t obj_size) {
    void *buf = malloc(count * obj_size);
    free(buf);
}
