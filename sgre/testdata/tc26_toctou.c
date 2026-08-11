#include <stdio.h>
#include <unistd.h>

void tc26_toctou(const char *path) {
    if (access(path, 0) == 0) {
        FILE *f = fopen(path, "r");
        if (f) fclose(f);
    }
}