/*
 * Phase 14 — IsDeallocator heuristic false-positive regression.
 *
 * poiner_in_bc_cache_free ends with "free" and was matched by the
 * IsDeallocator name-suffix heuristic. Its parameter is an integer cache
 * ID (a macro constant), not a freed pointer. The detector marked the ID
 * as freed, then a later call using the same ID constant
 * (free_cache_base_addr) was flagged as use-after-free.
 *
 * Fix: heuristic-only deallocators (not declared) require a function
 * summary confirming the body frees the parameter. External functions
 * without a summary are fail-closed.
 *
 * The free_cache_base_addr calls at lines 22 and 23 must NOT be reported
 * as use-after-free.
 */
#include <stdlib.h>

#define BC_ORG_M_CACHE_ID 1
#define BC_ORG_S_CACHE_ID 2

void bc_cache_mutex_lock(void);
void bc_cache_mutex_unlock(void);
void poiner_in_bc_cache_free(int cache_id);
void free_cache_base_addr(int cache_id);

void free_bc_cache(void)
{
    bc_cache_mutex_lock();
    poiner_in_bc_cache_free(BC_ORG_M_CACHE_ID);
    poiner_in_bc_cache_free(BC_ORG_S_CACHE_ID);
    free_cache_base_addr(BC_ORG_M_CACHE_ID);
    free_cache_base_addr(BC_ORG_S_CACHE_ID);
    bc_cache_mutex_unlock();
}