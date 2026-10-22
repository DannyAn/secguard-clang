/*
 * User-provided hrp_session.c form (null-deref audit example, CWD-1031/1034):
 *  - PATTERN-02: ctx reassigned from a tree-internal proven-nullable wrapper
 *    (`malloc` + `if (ctx == NULL) return NULL`) inside the `ctx == NULL`
 *    guard branch, then dereferenced with no re-check — auto-confirmable.
 *  - PATTERN-03: `ctx->negotiator->state` — the member pointer was assigned
 *    from an extern assumed-nullable lookup, dereferenced with no guard.
 *  - PATTERN-09: `msg->ctxPtr` (IPC external data) cast to a pointer and
 *    dereferenced with no validation — the untrusted-pointer form.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef enum { HRP_NEG_IDLE = 0, HRP_NEG_RUNNING = 1 } HrpNegState;

typedef struct HrpNegotiator {
    HrpNegState state;
} HrpNegotiator;

typedef struct HrpSessionCtx {
    uint32_t peerId;
    HrpNegotiator *negotiator;
    int active;
    unsigned long lastHeartbeat;
} HrpSessionCtx;

typedef struct HrpIpcMsg {
    unsigned long ctxPtr;
    uint32_t sessionId;
    unsigned long timestamp;
} HrpIpcMsg;

extern HrpNegotiator *Hrp_GetNegotiator(uint32_t peerId);

static HrpSessionCtx *Hrp_AllocSession(uint32_t peerId)
{
    HrpSessionCtx *ctx = (HrpSessionCtx *)malloc(sizeof(HrpSessionCtx));
    if (ctx == NULL) { return NULL; }
    (void)memset_s(ctx, sizeof(HrpSessionCtx), 0, sizeof(HrpSessionCtx));
    ctx->peerId = peerId;
    ctx->negotiator = Hrp_GetNegotiator(peerId);  /* 可能返回 NULL */
    return ctx;
}

void Hrp_ActivateSession(HrpSessionCtx *ctx, uint32_t peerId)
{
    if (ctx == NULL) {
        ctx = Hrp_AllocSession(peerId);            /* 返回值未判空 */
    }
    ctx->active = 1;                               /* PATTERN-02：可能解引用 NULL */
    ctx->negotiator->state = HRP_NEG_RUNNING;      /* PATTERN-03：成员指针可能为 NULL */
}

void Hrp_HandleIpcMsg(const HrpIpcMsg *msg)
{
    HrpSessionCtx *ctx = (HrpSessionCtx *)msg->ctxPtr;  /* PATTERN-09：IPC 外部数据强转 */
    ctx->lastHeartbeat = msg->timestamp;                 /* 未校验即解引用 */
}