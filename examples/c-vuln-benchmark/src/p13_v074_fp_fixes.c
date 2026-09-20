/*
 * Phase 13 — v0.7.4 false-positive regression guards.
 * Two production false positives reported in v0.7.4, each with two independent
 * root causes fixed in this release. These cases pin the fixes: the benchmark
 * validator asserts NO finding at the labelled lines.
 */

/* ---------------------------------------------------------------------------
 * UAF-02 — linked-list deletion with an indirect freeing wrapper.
 *
 * pktdrp_free_tbl_res is a custom wrapper (name does not end in "free") that
 * frees its argument. pktdrp_del_tbl_by_slot walks a singly-linked list with a
 * pre_item/item pair and reassigns pre_item before the free. Two root causes:
 *   1. findUseSites counted the wrapper's argument as a use (evidence layer).
 *   2. expandGenToAliases propagated a stale alias past the reassignment
 *      (planner layer).
 * The free at line 34 (and line 38) must NOT be reported as use-after-free.
 * ------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdlib.h>

typedef struct pktdrp_drop_key {
    uint8_t slot_id;
    uint8_t cpu_id;
} pktdrp_drop_key_t;

typedef struct pktdrp_tbl {
    pktdrp_drop_key_t drop_key;
    void *res;
    struct pktdrp_tbl *next;
} pktdrp_tbl_t;

static pktdrp_tbl_t *g_pktdrp_tbl;

static void pktdrp_free_tbl_res(pktdrp_tbl_t *item)
{
    if (item != NULL) {
        free(item->res);
        free(item);
    }
}

void pktdrp_del_tbl_by_slot(uint8_t slot_id, uint8_t cpu_id)
{
    pktdrp_tbl_t *item = g_pktdrp_tbl;
    pktdrp_tbl_t *pre_item = item;
    while (item != NULL) {
        if (item->drop_key.slot_id == slot_id && item->drop_key.cpu_id == cpu_id) {
            if (g_pktdrp_tbl == item) {
                g_pktdrp_tbl = item->next;
                pre_item = g_pktdrp_tbl;
                pktdrp_free_tbl_res(item);
                item = pre_item;
            } else {
                pre_item->next = item->next;
                pktdrp_free_tbl_res(item);
                item = pre_item->next;
            }
            continue;
        }
        pre_item = item;
        item = item->next;
    }
}

/* ---------------------------------------------------------------------------
 * SC-01 — signed-compare cross-scope name shadowing.
 *
 * The same name `i` is declared int in the first for-loop and unsigned in a
 * later, non-overlapping for-loop. The int i's `i >= 0` (line 82) is a
 * legitimate signed check and must NOT be flagged as an unsigned tautology
 * just because an out-of-scope `unsigned i` exists later in the function.
 * cmp_lookup_exception returns int (-1 or non-negative index), so the loop is
 * correct.
 * ------------------------------------------------------------------------- */

static void *g_exceptions[64];
static unsigned g_exception_num;

int cmp_lookup_exception(unsigned index, const char *vsys, const char *module)
{
    for (unsigned i = index; i < g_exception_num; i++) {
    }
    return -1;
}

void cmp_clear_exception(const char *vsys, const char *module)
{
    for (int i = cmp_lookup_exception(0, vsys, module);
         i >= 0; i = cmp_lookup_exception(i + 1, vsys, module)) {
        free(g_exceptions[i]);
        g_exceptions[i] = NULL;
    }

    unsigned count = 0;
    for (unsigned i = 0; i < g_exception_num; i++) {
        if (g_exceptions[i]) {
            g_exceptions[count] = g_exceptions[i];
            count++;
        }
    }
    g_exception_num = count;
}
/* ---------------------------------------------------------------------------
 * UC-01 — void function whose name contains "alloc".
 *
 * test_case_alloc returns void, so it has no return value to check. The alloc
 * heuristic (apikb.IsAllocator substring match) must not flag the call at
 * line 119 as unchecked-return. The malloc at line 117 IS a real unchecked
 * return and must still be flagged (control case).
 * ------------------------------------------------------------------------- */
typedef struct {
    int len;
} uc_mbuf;

void test_case_alloc(uc_mbuf *mbuf, int ecode)
{
    mbuf->len = ecode;
}

void uc_caller(void)
{
    uc_mbuf *mbuf = (uc_mbuf *)malloc(sizeof(uc_mbuf));
    if (mbuf == NULL) {
        return;
    }
    test_case_alloc(mbuf, 1);
    free(mbuf);
}
/* ---------------------------------------------------------------------------
 * UC-02 — scalar-returning function whose name contains "alloc".
 *
 * check_alloc_status returns int, so it can never return NULL. The alloc
 * heuristic must not flag the call as unchecked-return. This generalises
 * UC-01: any non-pointer return type (not just void) is not an allocator.
 * ------------------------------------------------------------------------- */
int check_alloc_status(int id)
{
    return id == 0;
}

void uc_scalar_caller(void)
{
    int ret = check_alloc_status(42);
    (void)ret;
}

/* ---------------------------------------------------------------------------
 * UC-03 — passthrough wrapper of a heuristic-matched allocator.
 *
 * my_alloc is matched by IsAllocator (name contains "alloc") but is not in
 * uncheckedReturnAPIs. passthrough_wrapper returns my_alloc's result, so it
 * must be recognised as a passthrough allocator — the transitive closure in
 * passthroughAllocFuncs must include the IsAllocator term, not just
 * uncheckedReturnAPIs. The caller's unchecked use of the result must be
 * flagged.
 * ------------------------------------------------------------------------- */
void *my_alloc(size_t n)
{
    return malloc(n);
}

void *passthrough_wrapper(size_t n)
{
    return my_alloc(n);
}

void uc_passthrough_caller(void)
{
    void *p = passthrough_wrapper(64);
    (void)p;
}