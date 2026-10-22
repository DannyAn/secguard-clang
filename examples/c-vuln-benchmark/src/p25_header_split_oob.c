#include "p25_header_split.h"

int show_hdr_active_server(struct maf_hdr_profile *rbl_profile, char *outbuf, int buflen, int *pos)
{
    int ret = maf_hdr_write_to_buffer(outbuf, buflen, pos,
        "    Active Server ID           : %u \n"
        "    Active Server Name         : %s \n"
        "    Query                      : %s \n",
        rbl_profile->actived_index,
        rbl_profile->actived_svr_name,
        rbl_profile->svr[rbl_profile->actived_index].domain);
    if (ret != 0) {
        return ret;
    }
    return maf_hdr_show_all_reply_code(&rbl_profile->svr[rbl_profile->actived_index], outbuf, buflen, pos);
}

int show_hdr_active_server_fix(struct maf_hdr_profile *p, char *outbuf, int buflen, int *pos)
{
    if (p->actived_index >= MAF_RBL_HDR_CFG_COUNT) {
        return 1;
    }
    return maf_hdr_show_all_reply_code(&p->svr[p->actived_index], outbuf, buflen, pos);
}
