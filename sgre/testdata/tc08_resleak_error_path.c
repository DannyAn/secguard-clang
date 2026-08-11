/*
 * TC08 - Resource Leak: Error Path Missing Close (REQ-TC-008)
 * Vulnerability: resource is closed on the success path but not on an
 *                error-return path.
 * Expected: finding produced (resource leak on error path)
 */

#include <stdio.h>

int tc08_resleak_error_path(const char *path, int fail) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    if (fail) {
        return -2;
    }

    int ch = fgetc(fp);
    fclose(fp);
    return ch;
}