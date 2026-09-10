#include "vsys.h"

typedef struct {
    int flag;
} stmp_userdata_t;

extern void notify_vsys(uint16_t vsys_id);

void stmp_usertbl_aging(uint16_t vrf_id, stmp_userdata_t *user_data)
{
    if (user_data->flag == 1) {
        return;
    }

    uint16_t vsys_id;
    vsys_get_vsysid_by_vrfindex(vrf_id, &vsys_id);
    notify_vsys(vsys_id);
}

void real_uninit(void)
{
    uint16_t v;
    notify_vsys(v);
}
