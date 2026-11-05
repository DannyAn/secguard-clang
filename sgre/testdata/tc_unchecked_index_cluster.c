/* Issue #216 item 3: the unchecked-external-index family.
 *
 * Several functions index a fixed-size array member through the same struct
 * field with no in-code bounds check. The bound is not provable in code; the
 * AI makes ONE external-bound judgment per (file, index-source field, capacity,
 * access flavor) and the folded sites stay listed. */

#define SVR_CNT 4

typedef struct svr_cfg {
    const char *domain;
    unsigned int code;
} svr_cfg_t;

typedef struct profile {
    unsigned int actived_index;
    svr_cfg_t svr[SVR_CNT];
} profile_t;

typedef struct small_profile {
    unsigned int idx;
    svr_cfg_t svr[2];
} small_profile_t;

/* ---- the repeated read shape: same field, same capacity, same flavor ---- */

int cluster_read_a(profile_t *p) {
    return p->svr[p->actived_index].code;
}

int cluster_read_b(profile_t *p) {
    return (int)p->svr[p->actived_index].code;
}

int cluster_read_c(profile_t *p) {
    return p->svr[p->actived_index].code + 1;
}

/* A different capacity is a different shape: a range that fits SVR_CNT does not
 * fit two elements, so the external-bound judgment is not the same. */
int other_capacity_read(small_profile_t *p) {
    return p->svr[p->idx].code;
}

/* ---- the repeated write shape ---- */

int cluster_write_a(profile_t *p) {
    p->svr[p->actived_index].code = 7;
    return 0;
}

int cluster_write_b(profile_t *p) {
    p->svr[p->actived_index].code = 8;
    return 0;
}

int cluster_write_c(profile_t *p) {
    p->svr[p->actived_index].code = 9;
    return 0;
}

/* ---- guards: an entry check against the capacity symbol seeds nothing ---- */

int guarded_read(profile_t *p) {
    if (p->actived_index >= SVR_CNT) {
        return -1;
    }
    return p->svr[p->actived_index].code;
}

int guarded_write(profile_t *p) {
    if (p->actived_index >= SVR_CNT) {
        return -1;
    }
    p->svr[p->actived_index].code = 7;
    return 0;
}
