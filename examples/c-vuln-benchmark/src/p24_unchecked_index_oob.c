/* Phase 24: unchecked external index into a fixed-size array.
 * A struct-field index (config/input supplied) used without a bounds check
 * against the array's capacity — the production maf_rbl shape: OOB read
 * (CWE-125) whose element pointer member feeds a null/wild-pointer deref.
 */
#define MAF_RBL_SVR_CFG_COUNT 4

typedef struct {
    const char *domain;
    unsigned int code;
} maf_rbl_svr_cfg_t;

typedef struct maf_rbl_profile {
    unsigned int actived_index;
    maf_rbl_svr_cfg_t svr[MAF_RBL_SVR_CFG_COUNT];
} maf_rbl_profile_t;

int maf_show_dataplane_config_all_reply_code(const maf_rbl_svr_cfg_t *svr)
{
    if (svr->domain[0] == '\0') {
        return -1;
    }
    return (int)svr->code;
}

int show_active(maf_rbl_profile_t *rbl_profile)
{
    unsigned int idx = rbl_profile->actived_index;
    const char *q = rbl_profile->svr[idx].domain;
    int rc = maf_show_dataplane_config_all_reply_code(&rbl_profile->svr[idx]);
    return q ? rc : -1;
}

int show_active_fix(maf_rbl_profile_t *p)
{
    if (p->actived_index >= MAF_RBL_SVR_CFG_COUNT) {
        return 1;
    }
    return (int)p->svr[p->actived_index].code;
}

void store_active(maf_rbl_profile_t *p)
{
    p->svr[p->actived_index].code = 7;
}

void copy_all(maf_rbl_profile_t *p, maf_rbl_svr_cfg_t *dst)
{
    for (unsigned int i = 0; i < MAF_RBL_SVR_CFG_COUNT; i++) {
        dst[i] = p->svr[i];
    }
}

unsigned int lookup(maf_rbl_profile_t *p, unsigned int n)
{
    return p->svr[n].code;
}
