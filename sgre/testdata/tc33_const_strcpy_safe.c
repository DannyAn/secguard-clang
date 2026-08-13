#include <stdlib.h>
#include <string.h>

void tc33_const_strcpy_safe() {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    strcpy(buf, "temporary");
    free(buf);
}
