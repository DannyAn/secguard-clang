#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct filter filter_t;

/* Entry guard: rejects a NULL filter with a failure code. */
int idm_fill_filter(filter_t *f, int n) {
    if (f == NULL) {
        return -1;
    }
    return 0;
}

/* No entry guard: dereferences the argument instead of validating it. */
int idm_touch_filter(filter_t *f, int n) {
    return f->count + n;
}

/* Polarity trap: the NULL branch returns SUCCESS, so a NULL argument is not
 * reported to the caller and this is not an entry guard. */
int idm_fill_success_on_null(filter_t *f, int n) {
    if (f == NULL) {
        return 0;
    }
    return 0;
}

/* Polarity trap: the branch taken when the argument is non-NULL returns. */
int idm_fill_notnull(filter_t *f, int n) {
    if (f != NULL) {
        return 0;
    }
    return 0;
}

/* The callee entry-guards its parameter and the caller checks the result, so
 * the allocation's failure has been handled: no unchecked-return event. */
void indirect_check_assign(int n) {
    filter_t *filter = malloc(n);
    int ret = idm_fill_filter(filter, n);
    if (ret != 0) {
        free(filter);
        return;
    }
    free(filter);
}

/* Same, with the callee's result tested inline. */
void indirect_check_inline(int n) {
    filter_t *filter = malloc(n);
    if (idm_fill_filter(filter, n) != 0) {
        free(filter);
        return;
    }
    free(filter);
}

/* The callee does not entry-guard, so the unchecked allocation is reported. */
void no_entry_guard(int n) {
    filter_t *filter = malloc(n);
    int ret = idm_touch_filter(filter, n);
    if (ret != 0) {
        free(filter);
        return;
    }
    free(filter);
}

/* A NULL argument is reported as success, so the caller's check proves nothing. */
void success_on_null_guard(int n) {
    filter_t *filter = malloc(n);
    int ret = idm_fill_success_on_null(filter, n);
    if (ret != 0) {
        free(filter);
        return;
    }
    free(filter);
}

/* The non-NULL branch returns; passing NULL is not validated. */
void nonnull_branch_guard(int n) {
    filter_t *filter = malloc(n);
    int ret = idm_fill_notnull(filter, n);
    if (ret != 0) {
        free(filter);
        return;
    }
    free(filter);
}

/* The argument is dereferenced by the call, not validated by it. */
void deref_not_guard(int n) {
    char *p = malloc(n);
    if (strlen(p) > 0) {
        free(p);
        return;
    }
    free(p);
}

/* No check at all: the allocation is dereferenced. (A pointer whose only use is
 * free(p) is deliberately NOT reported — free(NULL) is a no-op.) */
void no_check_unsafe(int n) {
    filter_t *filter = malloc(n);
    filter->count = n;
    free(filter);
}
