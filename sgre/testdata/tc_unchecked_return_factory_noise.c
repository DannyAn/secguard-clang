/*
 * Regression for the unchecked-return name heuristic: a call to a function
 * whose name matches the allocator heuristic (alloc/strdup/_new/_dup/_mem_create)
 * is a source by NAME only, not by failure contract. contract_known is false,
 * so the planner hands it to the AI (Hint contract@unknown) instead of
 * auto-confirming. The AI must prove the callee returns a failure sentinel or
 * dismiss. A never-null wrapper (xmalloc/aspf_safe_malloc) is excluded via
 * [nullability.non_null_returns].
 *
 * Expected UNCHECKED_RETURN events (all 5):
 *   call_factory_new / call_factory_db / call_copy_dup  -> 1 (name heuristic)
 *   call_mem_create / call_nat_alloc                     -> 1 (name heuristic)
 */

typedef struct { int v; } obj_t;

/* (excluded) object factory — mirrors idm_new_idmgr */
obj_t *idm_new_idmgr(int n);
/* (excluded) object factory — mirrors idm_db_filter_new */
obj_t *idm_db_filter_new(int n);
/* (excluded) copy helper — mirrors idm_asset_record_dup */
obj_t *idm_asset_record_dup(const obj_t *r, obj_t *out);
/* (kept) explicit raw-memory create */
void *pki_util_mem_create(int n);
/* (kept) alloc verb */
void *nat_malloc(int n);

void call_factory_new(int n)
{
    obj_t *p = idm_new_idmgr(n);
    (void)p;
}

void call_factory_db(int n)
{
    obj_t *p = idm_db_filter_new(n);
    (void)p;
}

void call_copy_dup(const obj_t *r)
{
    obj_t out;
    obj_t *p = idm_asset_record_dup(r, &out);
    (void)p;
}

void call_mem_create(int n)
{
    void *p = pki_util_mem_create(n);
    (void)p;
}

void call_nat_alloc(int n)
{
    void *p = nat_malloc(n);
    (void)p;
}