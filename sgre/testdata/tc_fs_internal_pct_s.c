/*
 * Format-string internal construction with a string conversion (issue #289 T5
 * reverse case). The buffer is built with snprintf using a %s conversion, so it
 * can carry caller-controlled bytes and the candidate must be kept.
 */

#include <stdio.h>

void diag_out(const char *fmt)
{
    printf(fmt);
}

void tc_fs_internal_pct_s(const char *user_str)
{
    char log_buf[128];
    (void)snprintf(log_buf, sizeof(log_buf), "%s", user_str);
    diag_out(log_buf);        /* 格式含 %s：必须保留候选 */
}
