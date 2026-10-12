/*
 * TC131 - Uninit: an output-param function whose spec'd output index is NOT the
 * argument being scanned. localtime_r/gmtime_r/gmtime_s/strptime are listed in
 * outputParamInitializerArgs with specific output arg indices, but a caller can
 * take the address of a DIFFERENT argument (`localtime_r(&now, &tm_buf)` — arg0
 * is an input `const time_t *`, arg1 is the output). The struct-uninit path then
 * evaluates `summary.ParamWrites[0]` for a call that has NO function summary
 * (localtime_r is external), dereferencing a nil *FuncSummary and panicking the
 * whole uninit detector. Reproduced on the redis codebase.
 */

typedef long time_t;
struct tm { int tm_year; int tm_hour; };

struct tm *localtime_r(const time_t *timep, struct tm *result);
struct tm *gmtime_r(const time_t *timep, struct tm *result);
struct tm *gmtime_s(const struct tm *timep, struct tm *result);

/* The panic shape: an ADDRESS-TAKEN input argument at a non-output index on a
 * call whose spec'd output indices exist but carry no function summary. */
int localtime_addr(time_t *src) {
    time_t now;
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    (void)src;
    return tm_buf.tm_year;
}

int gmtime_addr(time_t *src) {
    time_t now;
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    (void)src;
    return tm_buf.tm_hour;
}

int gmtime_s_addr(time_t *src) {
    time_t now;
    struct tm tm_buf;
    /* gmtime_s is registered with its Windows CRT argument order
     * ((struct tm *tm, const time_t *time)): arg0 is the output, arg1 is the
     * address-taken INPUT that reaches the nil-summary read. */
    gmtime_s(&tm_buf, &now);
    (void)src;
    return tm_buf.tm_year;
}

/* Control: a genuinely uninitialized struct field read is still reported. */
int no_init(void) {
    struct tm tm;
    return tm.tm_year;
}
