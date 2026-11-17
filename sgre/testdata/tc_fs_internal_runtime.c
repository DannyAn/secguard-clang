/*
 * Format-string internal-runtime buffer (issue #289 T5, pattern 10).
 * diag_out is a non-static format wrapper (printf sink) whose only in-tree
 * caller builds its argument with snprintf from a fixed format + integer
 * scalars ("session=%u state=%u"). That buffer cannot carry attacker-controlled
 * format specifiers, so the candidate must be eliminated.
 */

#include <stdio.h>

void diag_out(const char *fmt)
{
    printf(fmt);   /* format-string sink */
}

void tc_fs_internal_runtime(unsigned sid, unsigned st)
{
    char log_buf[128];
    (void)snprintf(log_buf, sizeof(log_buf), "session=%u state=%u", sid, st);
    diag_out(log_buf);        /* 内部运行期缓冲：不得报 format-string */
}
