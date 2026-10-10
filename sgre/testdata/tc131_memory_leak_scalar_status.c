/*
 * TC131 - Memory Leak: scalar status codes are not heap allocations
 * bool/int/uint32_t variables assigned from functions whose NAME triggers the
 * zero-config allocator heuristic (`_new`, `remalloc`, `*_alloc`) are status
 * codes, not pointers. They must NOT produce MEMORY_ALLOC events, while a real
 * pointer allocation (`char *buf = malloc(8)` never freed) still must.
 */
#include <stdlib.h>
#include <stdbool.h>

typedef unsigned int uint32_t;

int nlog_is_time_to_create_new(int t);
uint32_t nlog_disk_monitor_remalloc(void);
uint32_t nlog_disk_list_remalloc(void);
uint32_t HpeDynmemAlloc(int id, void **out);
int db_get_pssp_harddisk_new_mount_dir(int obj, char **dir);
uint32_t nlog_sub_pssp_harddisk_new_tbl(void);

int tc131_scalar_status(int obj) {
    bool ret1 = nlog_is_time_to_create_new(1);
    uint32_t ret2 = nlog_disk_monitor_remalloc();
    uint32_t ret3 = nlog_disk_list_remalloc();
    uint32_t resev2 = HpeDynmemAlloc(0, 0);
    int ret4 = db_get_pssp_harddisk_new_mount_dir(obj, 0);
    uint32_t ret5 = nlog_sub_pssp_harddisk_new_tbl();
    char *buf = malloc(8);
    return ret1 + ret2 + ret3 + resev2 + ret4 + ret5 + (buf != 0);
}
