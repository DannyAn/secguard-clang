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

void positive_control(void)
{
    char *p = malloc(100);
    free(p);
    char c = *p;
    (void)c;
}