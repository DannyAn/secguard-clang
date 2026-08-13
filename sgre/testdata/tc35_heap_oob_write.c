#include <stdlib.h>

void heap_oob_write(int user_len) {
    char *buf = (char *)malloc(user_len);
    if (!buf) return;
    for (int i = 0; i < user_len + 10; i++) {
        buf[i] = 'A';
    }
    free(buf);
}
