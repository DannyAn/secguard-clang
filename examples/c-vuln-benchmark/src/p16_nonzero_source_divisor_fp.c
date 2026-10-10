/*
 * Phase 16 — Divide-by-zero non-zero-source divisor false-positive regression.
 *
 * graph->gran_time is assigned from nlog_get_gran_time_by_flag, which always
 * returns a positive constant (60). g_thread_count is assigned from a non-zero
 * literal (4). Both are used as divisors without use-site guards.
 *
 * Before the fix, the RangeFilter stripped field-chain divisors to "" via
 * bareIdentVar, so invariants.NonZero was never checked for them. And
 * globalInvariants only tracked zero-guarded assignments, not assignments
 * from non-zero-returning functions or non-zero constants.
 *
 * The divisions at lines 22 and 30 must NOT be reported as divide-by-zero.
 */
#include <stdlib.h>
#include <stdint.h>

struct graph_info {
    uint32_t gran_time;
    uint32_t point_num;
};

uint32_t nlog_get_gran_time_by_flag(int flag) {
    return 60;
}

void init_graph(struct graph_info *graph, int flag) {
    graph->gran_time = nlog_get_gran_time_by_flag(flag);
}

uint32_t fp_field_divisor(struct graph_info *graph, uint32_t offset) {
    return offset / graph->gran_time;
}

static uint32_t g_thread_count = 0;

void init_threads(void) {
    g_thread_count = 4;
}

uint32_t fp_global_divisor(uint32_t index) {
    return index % g_thread_count;
}