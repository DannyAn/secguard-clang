/*
 * TC130 - Uninit: localtime_r/gmtime_r (POSIX) fill their `struct tm *` output
 * argument, so a later field read is initialized. They are external libc
 * functions with no body in the scan tree, so only the known-initializer list
 * (outputParamInitializers) can recognize the write.
 */

typedef long time_t;
struct tm { int tm_year; int tm_mon; int tm_mday; int tm_hour; int tm_min; int tm_sec; };

struct tm *localtime_r(const time_t *timep, struct tm *result);
struct tm *gmtime_r(const time_t *timep, struct tm *result);

int get_year(time_t *t) {
    struct tm local_tm;
    localtime_r(t, &local_tm);
    return local_tm.tm_year + 1900;
}

int get_hour_gm(time_t *t) {
    struct tm g_tm;
    gmtime_r(t, &g_tm);
    return g_tm.tm_hour;
}

/* Control: a struct field read with no initialization is a genuine uninit. */
int no_init(time_t *t) {
    struct tm tm;
    return tm.tm_year;
}
