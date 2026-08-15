#include <string.h>

typedef struct { char id[8]; char *path; } Log;

/* strcpy of a short literal into a fixed-size struct field is provably safe. */
int set_id(Log *log) {
    strcpy(log->id, "bad");
    return 0;
}

/* A literal that provably overflows the fixed field must still be flagged. */
int overflow_id(Log *log) {
    strcpy(log->id, "way_too_long_string_for_this_field");
    return 0;
}
