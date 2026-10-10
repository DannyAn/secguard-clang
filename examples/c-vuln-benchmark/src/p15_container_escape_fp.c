/*
 * Phase 15 — Memory-leak container-escape false-positive regression.
 *
 * xlog_CreateMsgPdu allocates a heap container (pduInfo) and a buffer
 * (pchBuf), writes the buffer pointer into the container via
 * *pduInfo = pchBuf, then returns the container. The buffer's ownership
 * transfers to the caller through the container — neither pchBuf nor
 * pduInfo leaks.
 *
 * Before the fix, findEscapeLines' pointer_expression branch used
 * !localVars[base] to decide escape. pduInfo is a local variable, so
 * the write *pduInfo = pchBuf was treated as a non-escaping store into
 * a stack slot, and pchBuf was falsely reported as leaked.
 *
 * The malloc at line 24 and the malloc at line 25 must NOT be reported
 * as memory-leak.
 */
#include <stdlib.h>

typedef char **MsgPdu;

MsgPdu xlog_CreateMsgPdu(void)
{
    MsgPdu pduInfo = (MsgPdu)malloc(sizeof(char *));
    if (!pduInfo)
        return NULL;

    char *pchBuf = (char *)malloc(100);
    if (!pchBuf) {
        free(pduInfo);
        return NULL;
    }

    *pduInfo = pchBuf;
    return pduInfo;
}