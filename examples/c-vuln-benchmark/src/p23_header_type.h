/*
 * Layout-visible types for the Phase 23 header-defined cases.
 *
 * This header defines NO function — the normal shape of a C project header,
 * and exactly the file the type census used to skip (forEachFile only visits
 * files containing an indexed function). While it was skipped, every in-tree
 * header type read as "opaque" and both fail-open channels seeded sources for
 * contracts the scan tree can see completely.
 */
typedef struct P23HdrRec_s {
    unsigned int len;
    unsigned int group_num;
    void *group_data;
} P23HdrRec_t;

typedef struct P23HdrNode_s {
    char group_name[32];
    unsigned int len;
} P23HdrNode_t;
