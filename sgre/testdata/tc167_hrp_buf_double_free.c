/*
 * User-provided hrp_buf.c double-free audit form:
 *  - PATTERN-01 (same-function): the error path frees buf, then goto jumps
 *    to the cleanup label (placed AFTER `return 0;`) which frees again —
 *    both frees execute on the rc != 0 path, a machine-proved double free.
 *  - PATTERN-06 (cross-function): queue_push frees its argument on its own
 *    failure branch (a MAY-free release helper), and the caller frees msg
 *    again after the rc check — a possible double free for the AI.
 */

#include <stdlib.h>
#include <string.h>

#define MAX_PKT_LEN 4096

typedef struct HrpPkt { int type; } HrpPkt;

extern int do_encode(HrpPkt *pkt, char *buf, int len);

static void log_err(const char *fmt, ...) { (void)fmt; }

int hrp_pkt_encode(HrpPkt *pkt, char **out, int *out_len)
{
    char *buf = (char *)malloc(MAX_PKT_LEN);
    if (buf == NULL) {
        return -1;
    }
    int rc = do_encode(pkt, buf, MAX_PKT_LEN);   /* 可能失败 */
    if (rc != 0) {
        free(buf);                                /* 第一次释放 */
        log_err("encode failed rc=%d", rc);
        goto cleanup;                             /* 跳到 cleanup 再次释放 */
    }
    *out = buf;
    *out_len = rc;
    return 0;
cleanup:
    free(buf);                                    /* 第二次释放 -> DOUBLE FREE */
    return -1;
}

char *hrp_msg_dup(const char *src)
{
    size_t n = strlen(src) + 1;
    char *dst = (char *)malloc(n);
    if (dst == NULL) {
        return NULL;
    }
    memcpy(dst, src, n);
    return dst;                                   /* 所有权交给调用方 */
}

static int queue_push(char *msg)
{
    extern int hrp_queue_full(void);
    if (hrp_queue_full()) {
        free(msg);                                /* 失败时内部释放 */
        return -1;
    }
    return 0;
}

int hrp_msg_build(const char *src)
{
    char *msg = hrp_msg_dup(src);
    if (msg == NULL) {
        return -1;
    }
    int rc = queue_push(msg);                     /* queue_push 失败时内部会 free(msg) */
    if (rc != 0) {
        free(msg);                                /* 调用方再次释放 -> DOUBLE FREE */
        return -1;
    }
    return 0;
}