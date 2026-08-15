#include <stdio.h>
#include <unistd.h>

void safe_open_literal(void) {
    FILE *f = fopen("/etc/config", "r"); /* safe: literal path */
    if (f) {
        fclose(f);
    }
}

void unsafe_open_var(const char *path) {
    FILE *f = fopen(path, "r"); /* PATH_TRAVERSAL: non-literal path */
    if (f) {
        fclose(f);
    }
}

void unsafe_unlink(const char *p) {
    unlink(p); /* PATH_TRAVERSAL */
}
