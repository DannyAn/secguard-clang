#include <stdlib.h>
#include <string.h>

void tc25_integer_overflow(unsigned int data_size, unsigned int raw_size) {
    if (data_size + 16 > raw_size) {
        return;
    }
    char *buf = (char *)malloc(data_size);
    memcpy(buf, "test", data_size);
}