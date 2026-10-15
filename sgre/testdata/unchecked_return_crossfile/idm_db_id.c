#include "idm_idmgr.h"

void *g_user_id_mgr = NULL;
void *g_user_grp_id_mgr = NULL;
void *g_sec_grp_id_mgr = NULL;

void idm_id_init(idmgr_cfg_t *cfg)
{
    g_user_grp_id_mgr = idm_new_idmgr(cfg);
    g_sec_grp_id_mgr = idm_new_idmgr(cfg);
}
