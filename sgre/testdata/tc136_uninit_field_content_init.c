/*
 * TC136 - uninit: a field-granular CONTENT write must cover a later subscript
 * read of that field. `p->data = malloc(...); memcpy(p->data, ...); ...
 * p->data[i]` used to key the element read on the full subscript text, which
 * never matched the field-level memcpy write, so a memcpy-filled member was
 * still reported as heap_uninit. A pointer-only assignment `p->data =
 * malloc(...)` without any content write must NOT cover the element read:
 * `p->data[0]` right after it reads uninitialized heap memory (the UN-05
 * field shape).
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct Pkt {
    uint8_t *data;
    uint32_t checksum;
};

/* memcpy writes the field content → the element reads are initialized:
 * must NOT be reported. */
void memcpy_content_covers_subscript(const uint8_t *raw) {
    struct Pkt *pkt_memcpy_ok = (struct Pkt *)malloc(sizeof(struct Pkt));
    pkt_memcpy_ok->data = (uint8_t *)malloc(64);
    memcpy(pkt_memcpy_ok->data, raw, 64);
    uint32_t sum = 0;
    for (uint32_t i = 0; i < 64; i++) {
        sum += pkt_memcpy_ok->data[i];
    }
    (void)sum;
    free(pkt_memcpy_ok->data);
    free(pkt_memcpy_ok);
}

/* Pointer-only assignment, no content write → the element read stays a
 * genuine uninitialized read: must be reported (UN-05 field shape). */
void malloc_pointer_only_subscript_reported(void) {
    struct Pkt *pkt_malloc_bad = (struct Pkt *)malloc(sizeof(struct Pkt));
    pkt_malloc_bad->data = (uint8_t *)malloc(64);
    uint8_t v = pkt_malloc_bad->data[0];
    (void)v;
    free(pkt_malloc_bad->data);
    free(pkt_malloc_bad);
}

/* A non-allocator pointer assignment (`p->data = buf`) also defines the
 * member content at field granularity for the heap-uninit tracker: the
 * buffer it now points at is tracked by its own (stack) analysis, not as
 * heap_uninit of the malloc'd struct. Must NOT be reported. */
void nonallocator_reassign_covers_subscript(void) {
    struct Pkt *pkt_reassign_ok = (struct Pkt *)malloc(sizeof(struct Pkt));
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    pkt_reassign_ok->data = buf;
    uint8_t v = pkt_reassign_ok->data[0];
    (void)v;
    free(pkt_reassign_ok);
}