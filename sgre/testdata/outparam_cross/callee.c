#include "vsys.h"

uint32_t (*g_vsys_get_vsysid_by_vrfindex)(uint16_t vrfindex, uint16_t *vsysid);

uint32_t vsys_get_vsysid_by_vrfindex(uint16_t vrfindex, uint16_t *vsysid)
{
    if (g_vsys_get_vsysid_by_vrfindex != NULL) {
        return g_vsys_get_vsysid_by_vrfindex(vrfindex, vsysid);
    }

    *vsysid = 0;
    return 1;
}
