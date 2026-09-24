#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef unsigned int uint32_t;

extern int g_dslitecar_dynm_id;
extern void *g_dslitecar_hash_tbl;

struct dslite_limit_info {
    uint32_t dslite_car_node_num;
};
extern struct dslite_limit_info g_stDslite_limit_Info;

uint32_t HpeDynmemGetInuseNumById(void *tbl) { return 0; }

void *HpeDynmemAlloc(int id, void **out)
{
    *out = malloc(100);
    return *out;
}

void *Car_Mem_Alloc(uint32_t mem_size)
{
    if (HpeDynmemGetInuseNumById(g_dslitecar_hash_tbl) >= g_stDslite_limit_Info.dslite_car_node_num) {
        return NULL;
    }

    void *new_node = NULL;
    (void)HpeDynmemAlloc(g_dslitecar_dynm_id, &new_node);
    if (new_node == NULL) {
        return NULL;
    }
    (void)memset(new_node, 0, mem_size);
    return new_node;
}

void *positive_control_void_malloc(void)
{
    (void)malloc(100);
    return NULL;
}
