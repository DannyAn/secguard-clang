/*
 * User remediation forms for the hrp_session/hrp_peer null-deref example:
 * fix 1 (checked reassignment + checked member), fix 2 (validate external
 * data + table lookup instead of the cast), fix 3 (entry null guard).
 * None of the three may surface a candidate.
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

typedef enum { HRP_STATE_INIT = 0, HRP_STATE_UP = 1 } HrpState;

typedef struct HrpPeer {
    HrpState state;
    unsigned long lastChange;
} HrpPeer;

extern HrpNegotiator *Hrp_GetNegotiator(uint32_t peerId);
extern HrpSessionCtx *Hrp_LookupSessionById(uint32_t sessionId);
extern unsigned long Hrp_GetTime(void);

#define HRP_LOG_ERROR(...) do { } while (0)

static HrpSessionCtx *Hrp_AllocSession(uint32_t peerId)
{
    HrpSessionCtx *ctx = (HrpSessionCtx *)malloc(sizeof(HrpSessionCtx));
    if (ctx == NULL) { return NULL; }
    (void)memset_s(ctx, sizeof(HrpSessionCtx), 0, sizeof(HrpSessionCtx));
    ctx->peerId = peerId;
    ctx->negotiator = Hrp_GetNegotiator(peerId);
    return ctx;
}

/* 用户修复 1：判空返回值 + 判空成员 */
void Hrp_ActivateSession(HrpSessionCtx *ctx, uint32_t peerId)
{
    if (ctx == NULL) {
        ctx = Hrp_AllocSession(peerId);
        if (ctx == NULL) { HRP_LOG_ERROR("alloc failed, peerId=%u", peerId); return; }
    }
    if (ctx->negotiator == NULL) { HRP_LOG_ERROR("negotiator null, peerId=%u", peerId); return; }
    ctx->active = 1;
    ctx->negotiator->state = HRP_NEG_RUNNING;
}

/* 用户修复 2：校验外部数据 + 查表替代强转 */
void Hrp_HandleIpcMsg(const HrpIpcMsg *msg)
{
    if (msg == NULL || msg->ctxPtr == 0) { HRP_LOG_ERROR("invalid ipc msg"); return; }
    HrpSessionCtx *ctx = Hrp_LookupSessionById(msg->sessionId);
    if (ctx == NULL) { HRP_LOG_ERROR("session not found, id=%u", msg->sessionId); return; }
    ctx->lastHeartbeat = msg->timestamp;
}

/* 用户修复 3：入口判空 */
void Hrp_UpdatePeerState(HrpPeer *peer, HrpState state)
{
    if (peer == NULL) { HRP_LOG_ERROR("peer is null"); return; }
    if (state == HRP_STATE_INIT) { peer->state = state; }
    peer->lastChange = Hrp_GetTime();
}