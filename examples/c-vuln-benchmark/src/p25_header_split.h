/*
 * Phase 25 — the production layout for the unchecked-index chain: the struct and
 * its capacity macro live in a HEADER, the analyzed function in a separate .c.
 *
 * Phase 24 kept both in one file, so the detector's file-scoped field/macro
 * census resolved the capacity and the fixture passed — while the production
 * function, whose struct is in a header, produced ZERO candidates. This header
 * pins the split-file shape.
 */
#ifndef P25_HEADER_SPLIT_H
#define P25_HEADER_SPLIT_H

#define MAF_RBL_HDR_CFG_COUNT 8

struct maf_hdr_svr {
    const char *domain;
    unsigned int action;
    unsigned int reply_code_any;
};

struct maf_hdr_profile {
    unsigned int actived_index;
    char actived_svr_name[64];
    struct maf_hdr_svr svr[MAF_RBL_HDR_CFG_COUNT];
};

extern int maf_hdr_write_to_buffer(char *outbuf, int buflen, int *pos, const char *fmt, ...);
extern int maf_hdr_show_all_reply_code(const struct maf_hdr_svr *svr, char *outbuf, int buflen, int *pos);

#endif
