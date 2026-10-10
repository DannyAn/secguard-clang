/*
 * TC127 - Divide-by-zero: a #define constant defined in a HEADER (not the .c
 * file) used as a divisor must resolve to its non-zero literal value and be
 * dropped. `NLOG_SECOND_PER_MINUTE`/`NLOG_PERCENT_100`/`NLOG_MSEC_PER_SEC` are
 * defined in types.h, so only a cross-file constant environment resolves them.
 */

#include "types.h"

int tc127_ticks_to_seconds(int ticks) {
    return ticks / NLOG_SECOND_PER_MINUTE;
}

int tc127_percent(int part, int total) {
    return part * NLOG_PERCENT_100 / total;
}

int tc127_ms_to_sec(int ms) {
    return ms / NLOG_MSEC_PER_SEC;
}
