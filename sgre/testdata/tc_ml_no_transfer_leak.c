/*
 * Memory-leak reverse case (issue #289 T1): use_ptr only READS its argument
 * (g_buf[0] = p[0]), it does not store the pointer into a non-local object,
 * so no ownership transfer is inferred. The success path therefore has no
 * release and q must still be reported as a leak.
 */

#include <stdlib.h>

static char g_buf[8];

int use_ptr(char *p)
{
    g_buf[0] = p[0];   /* 只读使用，不存储参数：不构成所有权转移 */
    return 0;
}

void tc_ml_no_transfer_leak(void)
{
    char *q = malloc(8);
    if (q == NULL) {
        return;
    }
    if (use_ptr(q) != 0) {
        free(q);
        return;
    }
    /* use_ptr 未取走所有权，成功路径无释放：真实泄漏 */
}
