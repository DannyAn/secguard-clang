#include <stdlib.h>

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

typedef struct {
    uint32_t cpe_ip;
    uint32_t key;
    uint16_t bitmap[4];
    char name[32];
} node_t;

void use_uint(uint32_t v);
void use_array(uint16_t *arr);
void use_name(const char *s);

/* memcpy_s(&p->cpe_ip, ...) writes p->cpe_ip — &p->field shape.
 * Previously the isDestWriter default branch only handled bare field_expression,
 * not pointer_expression (&p->f), so p->cpe_ip was mis-read as uninit (UN-15). */
void memcpy_s_addr_field_ok(uint32_t src_ip) {
    node_t *p = (node_t *)malloc(sizeof(node_t));
    if (!p) return;
    (void)memcpy_s(&p->cpe_ip, sizeof(p->cpe_ip), &src_ip, sizeof(src_ip));
    use_uint(p->cpe_ip);
    free(p);
}

/* memset_s(p->bitmap, ...) writes p->bitmap — bare field_expression (array
 * decays to pointer, no &). Previously the memset_s case only handled &p->f,
 * not bare p->f, so p->bitmap was mis-read as uninit (UN-15). */
void memset_s_bare_array_field_ok(void) {
    node_t *p = (node_t *)malloc(sizeof(node_t));
    if (!p) return;
    (void)memset_s(p->bitmap, sizeof(p->bitmap), 0xFF, sizeof(p->bitmap));
    use_array(p->bitmap);
    free(p);
}

/* strcpy_s(p->name, ...) writes p->name — bare field_expression, heap. */
void strcpy_s_bare_field_ok(const char *src) {
    node_t *p = (node_t *)malloc(sizeof(node_t));
    if (!p) return;
    (void)strcpy_s(p->name, sizeof(p->name), src);
    use_name(p->name);
    free(p);
}

/* strncpy_s(p->name, ...) with count — bare field_expression, heap. */
void strncpy_s_bare_field_ok(const char *src) {
    node_t *p = (node_t *)malloc(sizeof(node_t));
    if (!p) return;
    (void)strncpy_s(p->name, sizeof(p->name), src, sizeof(p->name) - 1);
    use_name(p->name);
    free(p);
}

/* memset_s(&p->key, ...) writes p->key — &p->field shape for memset_s. */
void memset_s_addr_field_ok(void) {
    node_t *p = (node_t *)malloc(sizeof(node_t));
    if (!p) return;
    (void)memset_s(&p->key, sizeof(p->key), 0, sizeof(p->key));
    use_uint(p->key);
    free(p);
}

/* A field never written stays genuinely uninitialized — regression guard.
 * Uses a distinct variable name so the test can assert this one IS reported
 * while the safe-function cases above are NOT. */
void field_never_written_ok(void) {
    node_t *uninit_p = (node_t *)malloc(sizeof(node_t));
    if (!uninit_p) return;
    uninit_p->key = 1;
    use_uint(uninit_p->cpe_ip); /* cpe_ip never written → heap_uninit */
    free(uninit_p);
}