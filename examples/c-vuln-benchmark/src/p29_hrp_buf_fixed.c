/*
 * User remediation for the hrp_buf.c double-free audit form:
 *  - fix 1: the error path logs then goto's to the SINGLE cleanup free,
 *    followed by an immediate null assignment.
 *  - fix 2: queue_push no longer frees internally (ownership contract
 *    corrected — the caller is the only releaser).
 * Neither form may surface a double-free candidate.
 */

#include <stdlib.h>
#include <string.h>

#define MAX_PKT_LEN 4096

typedef struct HrpPkt { int type; } HrpPkt;

extern int do_encode(HrpPkt *pkt, char *buf, int len);

static void log_err(const char *fmt, ...) { (void)fmt; }

/* 用户修复 1：失败统一走 cleanup，单一释放点 + 释放后置空 */
int hrp_pkt_encode_fixed(HrpPkt *pkt, char **out, int *out_len)
{
    char *buf = (char *)malloc(MAX_PKT_LEN);
    if (buf == NULL) {
        return -1;
    }
    int rc = do_encode(pkt, buf, MAX_PKT_LEN);
    if (rc != 0) {
        log_err("encode failed rc=%d", rc);
        goto cleanup;                             /* 失败统一走 cleanup */
    }
    *out = buf;
    *out_len = rc;
    return 0;
cleanup:
    free(buf);
    buf = NULL;                                   /* 释放后立即置空 */
    return -1;
}

/* 用户修复 2：queue_push 失败时不再内部释放，仅由调用方释放一次 */
static int queue_push_fixed(char *msg)
{
    extern int hrp_queue_full(void);
    if (hrp_queue_full()) {
        return -1;
    }
    return 0;
}

int hrp_msg_build_fixed(const char *src)
{
    char *msg = hrp_msg_dup_fixed(src);
    if (msg == NULL) {
        return -1;
    }
    int rc = queue_push_fixed(msg);
    if (rc != 0) {
        free(msg);                                /* 仅由调用方释放一次 */
        msg = NULL;
        return -1;
    }
    return 0;
}

static char *hrp_msg_dup_fixed(const char *src)
{
    size_t n = strlen(src) + 1;
    char *dst = (char *)malloc(n);
    if (dst == NULL) {
        return NULL;
    }
    memcpy(dst, src, n);
    return dst;
}