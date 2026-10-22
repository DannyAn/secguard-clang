/*
 * User-provided hrp_peer.c form (null-deref audit example, PATTERN-05):
 * `peer` is a function parameter dereferenced both inside a condition branch
 * (whose condition tests `state`, NOT the pointer) and on the fall-through
 * path with no null guard — the incomplete-guard form.
 */

#include <stdint.h>

typedef enum { HRP_STATE_INIT = 0, HRP_STATE_UP = 1 } HrpState;

typedef struct HrpPeer {
    HrpState state;
    unsigned long lastChange;
} HrpPeer;

extern unsigned long Hrp_GetTime(void);

void Hrp_UpdatePeerState(HrpPeer *peer, HrpState state)
{
    if (state == HRP_STATE_INIT) {
        peer->state = state;        /* 仅条件分支内解引用（条件与 peer 无关） */
    }
    peer->lastChange = Hrp_GetTime();  /* PATTERN-05：分支外解引用未判空 */
}