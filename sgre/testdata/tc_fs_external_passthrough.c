/*
 * Format-string external passthrough (issue #289 T5 reverse case).
 * The caller passes a parameter straight through to diag_out, so the format
 * argument is attacker-reachable and the candidate must be kept.
 */

#include <stdio.h>

void diag_out(const char *fmt)
{
    printf(fmt);
}

void tc_fs_external_passthrough(const char *user_input)
{
    diag_out(user_input);     /* 外部数据直通：必须保留候选 */
}
