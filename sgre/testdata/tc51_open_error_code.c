#include <stdio.h>

#define UNZ_OK 0

/* Returns an error code (int), not a resource handle, despite "Open" in the
 * name. The result is compared against UNZ_OK, so it must not be flagged as a
 * leaked resource. */
static int unzOpenCurrentFilePassword(void *file, const char *password) {
    (void)file; (void)password;
    return UNZ_OK;
}

int use_error_code(void *uf) {
    int err = unzOpenCurrentFilePassword(uf, "pw");
    if (err != UNZ_OK) {
        return -1;
    }
    return 0;
}

/* A genuine FILE* that is never closed must still be flagged. */
int genuine_resource_leak(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    return 0; /* f leaked */
}
