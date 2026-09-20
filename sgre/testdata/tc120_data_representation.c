/* Contract data-representation fixtures (CWE-843 type confusion via qsort). */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static int cmp_scalar(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int cmp_ptr(const void *a, const void *b)
{
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    return strcmp(sa, sb);
}

/* POSITIVE: char buffer (element depth 0) sorted with a pointer comparator
 * (element depth 1) — reads the string's first bytes as a char *. */
void sort_chars_wrong(void)
{
    char buf[16] = "hello";
    qsort(buf, 5, sizeof(char), cmp_ptr);
}

/* NEGATIVE 1: char buffer with a scalar comparator (depth 0 == depth 0). */
void sort_chars_right(void)
{
    char buf[16] = "hello";
    qsort(buf, 5, sizeof(char), cmp_scalar);
}

/* NEGATIVE 2: char * array with the pointer comparator (depth 1 == depth 1). */
void sort_ptrs_right(void)
{
    char *arr[3] = {"c", "a", "b"};
    qsort(arr, 3, sizeof(char *), cmp_ptr);
}
