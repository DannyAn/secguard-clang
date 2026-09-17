#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct config {
    int type;
    int flags;
    char name[64];
};

struct pair {
    int a;
    int b;
};

typedef struct msg {
    int status;
    int len;
} msg_t;

/* H1/H3: direct field assignment, then read an unassigned field → report. */
int h_bad(void) {
    struct config cfg_bad;
    cfg_bad.type = 1;
    if (cfg_bad.flags & 0x01) {
        return 1;
    }
    return 0;
}

/* H good: only use the assigned field → no report. */
int h_good(void) {
    struct config cfg_good;
    cfg_good.type = 1;
    return cfg_good.type;
}

/* Designated initializer: per C11 6.7.9 p19/p21 the non-designated fields are
 * zero-initialized, so this is NOT a defect. */
int designated(void) {
    struct pair p_des = { .a = 1 };
    return p_des.b;
}

/* Heap-S1: malloc then read a field with no init at all → report. */
int heap_s1(void) {
    msg_t *m_s1 = (msg_t *)malloc(sizeof(msg_t));
    if (m_s1 == NULL) return -1;
    int s = m_s1->status;
    free(m_s1);
    return s;
}

/* Heap partial: malloc then init one field, read another → report. */
int heap_partial(void) {
    msg_t *m_partial = (msg_t *)malloc(sizeof(msg_t));
    if (m_partial == NULL) return -1;
    m_partial->status = 1;
    int l = m_partial->len;   /* len still uninitialized */
    free(m_partial);
    return l;
}

/* Heap good: memset whole block → no report. */
int heap_memset_good(void) {
    msg_t *m_good = (msg_t *)malloc(sizeof(msg_t));
    if (m_good == NULL) return -1;
    memset(m_good, 0, sizeof(*m_good));
    int s = m_good->status;
    free(m_good);
    return s;
}

/* Partial memset of one field, then read another field → report. */
int partial_memset(void) {
    struct config cfg_pm;
    memset(&cfg_pm.type, 0, sizeof(cfg_pm.type));
    if (cfg_pm.flags) {   /* flags uninitialized */
        return 1;
    }
    return 0;
}

/* Whole memset of the struct → no report. */
int whole_memset(void) {
    struct config cfg_wm;
    memset(&cfg_wm, 0, sizeof(cfg_wm));
    return cfg_wm.flags;
}
