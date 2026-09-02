#include <stdio.h>
#include <dirent.h>

#define FILE_NAME "x"

void inline_guard_fopen(void) {
    FILE *fp = NULL;
    if ((fp = fopen(FILE_NAME, "at+")) == NULL) {
        return;
    }
    fclose(fp);
}

void inline_guard_fopen_neq(void) {
    FILE *fp = NULL;
    if ((fp = fopen(FILE_NAME, "a")) == NULL) {
        return;
    }
    fclose(fp);
}

void inline_guard_opendir(char *disk_path) {
    DIR *dir;
    if ((dir = opendir(disk_path)) == NULL) {
        return;
    }
    closedir(dir);
}

void control_unchecked(void) {
    FILE *fp = fopen(FILE_NAME, "r");
    fputs("hi", fp); /* UNCHECKED_RETURN: no check on fp */
    fclose(fp);
}
