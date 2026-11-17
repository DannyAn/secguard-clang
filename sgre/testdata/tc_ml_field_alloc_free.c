/*
 * TC - Memory Leak: struct field allocation + same-field free (Issue #288)
 * `s.buf = malloc(...)` must pair with `free(s.buf)` / `PROJ_FREE(s.buf)` by the
 * SAME base+field tracking key, and a whole-struct `cleanup(&s)` must still
 * release every field allocation. Distinct fields stay distinct: freeing one
 * field must not hide a leak of a sibling field.
 */

#include <stdlib.h>

typedef struct {
    unsigned char *buf;
    unsigned int   buf_size;
} import_param_t;

typedef struct {
    unsigned char *a;
    unsigned char *b;
} pair_t;

extern void cleanup_288(pair_t *p);

extern int fail_288(void);

#define PROJ_FREE_288(x) free(x)

/* Case 1: field alloc + same-field free on every path — no leak. */
int ml288_field_free_all_paths(void)
{
    import_param_t param = {0};
    param.buf_size = 32;
    param.buf = (unsigned char *)malloc(param.buf_size);
    if (param.buf == NULL) {
        return -1;
    }
    if (fail_288()) {
        free(param.buf);
        return -1;
    }
    free(param.buf);
    return 0;
}

/* Case 2: field alloc + same-field free through a freeing macro — no leak. */
int ml288_field_free_macro(void)
{
    import_param_t param = {0};
    param.buf_size = 32;
    param.buf = (unsigned char *)malloc(param.buf_size);
    if (!param.buf) {
        return -1;
    }
    if (fail_288()) {
        PROJ_FREE_288(param.buf);
        return -1;
    }
    PROJ_FREE_288(param.buf);
    return 0;
}

/* Case 3: distinct fields — freeing `a` must still report the `b` leak. */
int ml288_distinct_fields(void)
{
    pair_t s;
    s.a = (unsigned char *)malloc(1);
    s.b = (unsigned char *)malloc(1);
    free(s.a);
    return 0; /* s.b leaks */
}

/* Case 4: whole-struct cleanup releases every field — no leak. */
int ml288_whole_struct_cleanup(void)
{
    pair_t s;
    s.a = (unsigned char *)malloc(1);
    s.b = (unsigned char *)malloc(1);
    cleanup_288(&s);
    return 0;
}

/* Case 5: a genuine leak path (early return without free) — still reports. */
int ml288_real_leak(void)
{
    import_param_t param = {0};
    param.buf_size = 32;
    param.buf = (unsigned char *)malloc(param.buf_size);
    if (!param.buf) {
        return -1;
    }
    if (fail_288()) {
        return -1; /* leak: no free on this path */
    }
    free(param.buf);
    return 0;
}
