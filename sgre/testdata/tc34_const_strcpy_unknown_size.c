#include <stdlib.h>
#include <string.h>

void tc34_const_strcpy_unknown_size(int user_size) {
    char *buf = (char *)malloc(user_size);
    if (!buf) return;
    strcpy(buf, "initialized");
    free(buf);
}
