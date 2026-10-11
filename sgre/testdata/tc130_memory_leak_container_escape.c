/*
 * TC130 - Memory Leak: two-step container escape (*container = buf)
 * pduInfo is a malloc'd pointer-to-pointer container; pchBuf is a malloc'd
 * buffer stored into *pduInfo (a dereferenced container pointer). The container
 * is returned to the caller (ownership-transfer), and the buffer rides along
 * inside it, so pchBuf must NOT be reported as a leak on its own.
 *
 * findEscapeLines must treat `*container = buf` as an escape when the base is
 * ITSELF a malloc allocation (points into the heap, not the stack): the buffer
 * is owned by the container, whose lifetime is tracked separately by the
 * container's own allocation.
 */

#include <stdlib.h>

typedef char **MsgPdu;

MsgPdu tc130_create_msgpdu(void)
{
    MsgPdu pduInfo = (MsgPdu)malloc(sizeof(char *));
    if (pduInfo == NULL) {
        return NULL;
    }

    char *pchBuf = (char *)malloc(100);
    if (pchBuf == NULL) {
        free(pduInfo);
        return NULL;
    }

    *pduInfo = pchBuf;

    return pduInfo;
}
