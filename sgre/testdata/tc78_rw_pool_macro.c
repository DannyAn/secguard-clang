#include <stdint.h>
#include <stddef.h>

typedef struct rw_query_handle rw_query_handle_t;
typedef struct rw_pool rw_pool_t;

#define ID_INVALID ((uint16_t)0xFFFF)
#define RW_POOL_GROUP(pool_id) ((rw_pool_t *)(uintptr_t)(pool_id))

uint16_t rw_pool_first_group(uint16_t vsys_id);

inline static uint16_t rw_pool_next_group(uint16_t pool_id)
{
    return RW_POOL_GROUP(pool_id)->vsys_next;
}

#define RW_POOL_FOR(group_id, pool_id)                                          \
    for ((pool_id) = rw_pool_first_group(group_id); ID_INVALID != (pool_id);    \
         (pool_id) = rw_pool_next_group((pool_id)))

int count;

void test(rw_query_handle_t *query_handle) {
    uint16_t pool_id;
    RW_POOL_FOR(query_handle->grouu_id, pool_id)
    {
        count++;
    }
}
