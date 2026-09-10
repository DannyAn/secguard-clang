#include <stdlib.h>

typedef unsigned int uint32_t;
#define HPE_ERR 1

uint32_t testcase(void *recvMsg, uint16_t recvLen, void **retMsg, uint16_t *retLen)
{
    *retMsg = NULL;
    *retLen = 0;

    *retMsg = malloc(100);
    if (*retMsg == NULL) {
        return HPE_ERR;
    }
    return 0;
}

void g(void) {
    char *p = malloc(100);
    p[0] = 'x'; /* 未检查就解引用：真实 unchecked-return，应保留 */
}

