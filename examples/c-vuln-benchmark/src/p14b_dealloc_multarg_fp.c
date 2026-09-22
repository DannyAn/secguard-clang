/*
 * Phase 14b — IsDeallocator heuristic double-free false-positive regression.
 *
 * seccloud_send_list_free ends with "free" and was matched by the
 * IsDeallocator heuristic. It takes TWO arguments: a pointer and an integer
 * count. The detector marked BOTH as freed, so two calls with the same
 * constant count (LOGSEND_MAX_NUM) produced a false double-free on the
 * count variable.
 *
 * Fix: heuristic-only deallocators require a function summary confirming
 * which parameters are freed; only those are marked. External functions
 * without a summary are fail-closed.
 *
 * The second seccloud_send_list_free call at line 24 must NOT be reported
 * as double-free.
 */
#include <stdlib.h>
#include <string.h>

#define LOGSEND_MAX_NUM 16

typedef struct {
    void *buf[2];
} seccloud_save_entry_t;

seccloud_save_entry_t g_seccloud_save_buf[4];

void seccloud_send_list_free(void *ptr, int max_num);

void seccloud_free_save_buf(unsigned int log_type)
{
    seccloud_send_list_free(g_seccloud_save_buf[log_type].buf[0], LOGSEND_MAX_NUM);
    seccloud_send_list_free(g_seccloud_save_buf[log_type].buf[1], LOGSEND_MAX_NUM);
    memset(g_seccloud_save_buf, 0, sizeof(g_seccloud_save_buf));
}