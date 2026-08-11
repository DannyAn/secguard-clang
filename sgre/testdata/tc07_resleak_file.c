/*
 * TC07 - Resource Leak: File Open Without Close (REQ-TC-007)
 * Vulnerability: a file opened via fopen is never closed.
 * Expected: RESOURCE_RELEASE event absent; finding produced (resource leak)
 */

#include <stdio.h>

int tc07_resleak_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    int ch = fgetc(fp);
    return ch;
}