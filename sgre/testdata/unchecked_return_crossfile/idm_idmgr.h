#ifndef IDM_IDMGR_H
#define IDM_IDMGR_H

typedef struct {
    int min_id;
    int max_id;
} idmgr_cfg_t;

typedef struct idmgr_s {
    int min_id;
    int max_id;
    void *data;
} idmgr_t;

void *idm_new_idmgr(idmgr_cfg_t *cfg);

#endif
