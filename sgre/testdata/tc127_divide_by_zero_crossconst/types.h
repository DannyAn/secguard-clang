/* Header-defined compile-time constants. The divisor in main.c is
 * NLOG_SECOND_PER_MINUTE, defined here (not in the .c file), so only a
 * cross-file constant environment can resolve it to the non-zero literal 60. */
#define NLOG_SECOND_PER_MINUTE 60
#define NLOG_PERCENT_100 100
#define NLOG_MSEC_PER_SEC 1000
