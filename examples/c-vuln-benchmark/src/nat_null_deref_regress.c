/*
 * NAT production round-2 regression (CWE-476)
 *
 * ND-14: POOL_SECT-style getter `return g_pool_var.sects + node_id` is
 *        pointer arithmetic on a static array base — the result is an
 *        address inside (or one past) the array and can never be NULL.
 *        The unchecked call-site dereference must NOT be flagged.
 * ND-15: the same getter wrapped behind a literal-NULL return path IS a
 *        real null-deref at the unchecked call site — must still be
 *        flagged (control for ND-14).
 */

#include <stdlib.h>

#define POOL_MAX_SECT 64

typedef struct { unsigned int node_id; unsigned short flag; } pool_sect_t;
typedef struct { pool_sect_t sects[POOL_MAX_SECT]; unsigned int sect_cnt; } pool_var_t;

pool_var_t g_pool_var;

static pool_sect_t *POOL_SECT(unsigned int node_id)
{
    return g_pool_var.sects + node_id;
}

static pool_sect_t *find_opt(unsigned int node_id)
{
    if (node_id >= g_pool_var.sect_cnt) { return NULL; }
    return POOL_SECT(node_id);
}

/* ND-14: array-base pointer arithmetic never yields NULL — no_finding */
void pool_update_flag(unsigned int node_id, unsigned short flag) {
    pool_sect_t *sect = POOL_SECT(node_id);
    sect->flag = flag;
}

/* ND-15: find_opt returns literal NULL on overflow — finding */
void real_null_bug(unsigned int node_id) {
    pool_sect_t *sect = find_opt(node_id);
    sect->flag = 1;
}