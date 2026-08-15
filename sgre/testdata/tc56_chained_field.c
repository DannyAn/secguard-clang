typedef struct { int sec; int min; int hour; } Time;
typedef struct { Time tm; int dos; } Info;

/* Chained field assignment writes every sub-field; the base `info.tm` is a
 * write target, not an uninitialized read. */
int fill_info(void) {
    Info info;
    info.tm.sec = info.tm.min = info.tm.hour = 0;
    info.dos = 0;
    return info.tm.sec + info.dos;
}

/* A top-level field genuinely never set must still be flagged. */
int partial_init(void) {
    Info other;
    other.tm.sec = 1;
    return other.dos; /* dos never initialized */
}
