#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int count;
    int max_num;
    int items[0];
} filter_t;

typedef struct {
    char *user_filter;
    char *dst_name;
} para_t;

typedef struct {
    int len;
    char data[0];
} blob_t;

/* Name carries the *_new allocator heuristic; genuinely returns NULL on OOM. */
void *filter_new(int max_num)
{
    filter_t *f = (filter_t *)malloc(sizeof(filter_t) + sizeof(int) * (size_t)max_num);
    if (f == NULL) {
        return NULL;
    }
    f->count = 0;
    f->max_num = max_num;
    return f;
}

/* Consumer 1: entry guard through a CAST ALIAS of the parameter
 * (`filter_t *ft = (filter_t *)f; if (ft == NULL ...) return -1;`). */
int filter_add(void *f, int item)
{
    filter_t *ft = (filter_t *)f;
    if (ft == NULL || ft->count >= ft->max_num) {
        return -1;
    }
    ft->items[ft->count++] = item;
    return 0;
}

/* Consumer 2: void with an entry NULL guard. */
void filter_free(void *f)
{
    if (f == NULL) {
        return;
    }
    free(f);
}

/* Consumer 3: positive guard — a NULL argument takes the no-filter branch. */
int filter_traverse(void *f)
{
    if (f != NULL) {
        return filter_add(f, 1);
    }
    return 0;
}

/* Dereferences the argument with no guard: not null-safe. */
int filter_touch_unsafe(void *f, int item)
{
    filter_t *ft = (filter_t *)f;
    return ft->items[ft->count] + item;
}

/* Name carries the strdup allocator heuristic; returns NULL on failure. */
char *import_strdup(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d == NULL) {
        return NULL;
    }
    memcpy(d, s, n);
    return d;
}

/* Shared downstream validator: NULL member -> failure return. */
int para_is_valid(const para_t *p)
{
    if (p->user_filter == NULL || p->dst_name == NULL) {
        return -1;
    }
    return 0;
}

void para_free(para_t *p)
{
    free(p->user_filter);
    free(p->dst_name);
}

blob_t *blob_dup(const char *s)
{
    size_t n = strlen(s) + 1;
    blob_t *b = (blob_t *)malloc(sizeof(blob_t) + n);
    if (b == NULL) {
        return NULL;
    }
    b->len = (int)n;
    memcpy(b->data, s, n);
    return b;
}

/* Report shape 4.1: the consumers mix a discarded int result, a positive-guard
 * traverse, and a void free — every consumer of f is null-safe, so the
 * filter_new store must NOT be reported. */
int query_by_name(int key)
{
    void *f = filter_new(2);
    (void)filter_add(f, key);
    (void)filter_traverse(f);
    filter_free(f);
    return 0;
}

/* Report shape A2 (no void consumer): every consumer returns int and the
 * results are deliberately discarded; the consumers guard the argument, so a
 * NULL f cannot be dereferenced anywhere. */
int query_by_name2(int key)
{
    void *f = filter_new(2);
    (void)filter_add(f, key);
    filter_traverse(f);
    return 0;
}

/* Report shape 4.2: the allocations land in struct fields that the shared
 * downstream validator checks against NULL with a failure return. */
int fill_and_run(const char *flt, const char *name)
{
    para_t para;
    memset(&para, 0, sizeof(para));
    para.user_filter = import_strdup(flt);
    para.dst_name = import_strdup(name);
    if (para_is_valid(&para) != 0) {
        para_free(&para);
        return -1;
    }
    para_free(&para);
    return 0;
}

/* Report shape 4.3 (true positive): the allocation is dereferenced directly. */
int process(const char *s)
{
    blob_t *b = blob_dup(s);
    return b->len + b->data[0];
}

/* Discarded result, but the consumer dereferences the argument: the census
 * must keep the event. */
int neg_discard_unsafe(int key)
{
    void *f = filter_new(2);
    (void)filter_touch_unsafe(f, key);
    return 0;
}

/* Census AND: one null-safe consumer plus one direct dereference — the
 * dereference disqualifies the suppression. */
int neg_census_and(int key)
{
    void *f = filter_new(2);
    (void)filter_add(f, key);
    ((filter_t *)f)->count = key;
    return 0;
}

/* void consumer whose dereferences are all wrapped in a positive guard. */
void guarded_consumer(void *f)
{
    if (f != NULL) {
        ((filter_t *)f)->count = 1;
    }
}

int pos_void_guarded_body(int key)
{
    void *f = filter_new(2);
    guarded_consumer(f);
    return 0;
}

/* Value escape with no guard and no dereference: the stashed pointer leaves
 * the callee unchecked, so the event must stay. */
static void *g_stashed;

void stash_ptr(void *f)
{
    g_stashed = f;
}

int neg_stash_escape(int key)
{
    void *f = filter_new(2);
    stash_ptr(f);
    return 0;
}