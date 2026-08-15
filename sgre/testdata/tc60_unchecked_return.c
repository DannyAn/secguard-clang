#include <stdlib.h>
#include <stdio.h>

int checked_malloc(void) {
    int *p = (int *)malloc(sizeof(int) * 10);
    if (p == NULL) {
        return -1;
    }
    return p[0]; /* checked: p == NULL */
}

int unchecked_malloc(void) {
    int *p = (int *)malloc(sizeof(int) * 10);
    return p[0]; /* UNCHECKED_RETURN: no NULL check */
}

int checked_fopen(void) {
    FILE *f = fopen("x", "r");
    if (!f) {
        return -1;
    }
    fclose(f);
    return 0;
}

int unchecked_fopen(void) {
    FILE *f = fopen("x", "r");
    fputs("hi", f); /* UNCHECKED_RETURN: no check on f */
    fclose(f);
    return 0;
}
