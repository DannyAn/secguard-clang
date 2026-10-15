#include "idm_idmgr.h"
#include <stdlib.h>

void *idm_new_idmgr(idmgr_cfg_t *cfg)
{
    idmgr_t *mgr = (idmgr_t *)malloc(sizeof(idmgr_t));
    if (mgr == NULL) {
        return NULL;
    }
    mgr->min_id = cfg->min_id;
    mgr->max_id = cfg->max_id;
    return mgr;
}
