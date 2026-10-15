/*
 * Regression for the unchecked-return global-store false positive: a factory
 * whose name matches the allocator heuristic (`_new`), stored into a file-scope
 * (global) variable, must NOT be an unchecked-return source. The "check" for a
 * global is cross-function (its use sites in other functions, or a lazy-init
 * guard), invisible to the function-scoped detector, and the contract is only a
 * name guess. A genuine NULL global is caught by null-deref at its use site.
 *
 * Expected UNCHECKED_RETURN events:
 *   id_init                -> 0 (global store of a `_new` heuristic factory)
 *   id_init_local          -> 1 (local store of the same factory: contract@unknown lead)
 *   id_init_malloc_global  -> 1 (declared allocator malloc to a global: real CWE-252)
 */

typedef struct { int min_id; int max_id; } idmgr_cfg_t;

void *g_user_id_mgr = NULL;
void *g_user_grp_id_mgr = NULL;
void *g_sec_grp_id_mgr = NULL;

void *idm_new_idmgr(idmgr_cfg_t *cfg);

void id_init(idmgr_cfg_t *cfg)
{
    g_user_grp_id_mgr = idm_new_idmgr(cfg);
    g_sec_grp_id_mgr = idm_new_idmgr(cfg);
}

void id_init_local(idmgr_cfg_t *cfg)
{
    void *p = idm_new_idmgr(cfg);
    (void)p;
}

void id_init_malloc_global(void)
{
    g_user_id_mgr = malloc(16);
}
