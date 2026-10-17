/*
 * P17 — 补齐三个此前零覆盖的注册类型：argument-type / data-representation /
 * implicit-contract。
 *
 * 每类都给出「该报」与「不该报」对照，锁定 contract 类判据的召回与精度：
 *   - argument-type (CWE-686)：显式指针 cast 让 callee 读多于源对象字节。
 *   - data-representation (CWE-843)：qsort/bsearch 的 base 元素表示与 comparator
 *     对 void* 的解释不一致。
 *   - implicit-contract (CWE-20)：caller/framework 提供的结构体指针字段在一条路径
 *     上被 null-check、另一条路径上无守卫解引用。
 *
 * 仅作为 ground truth 的扫描目标；分类判据见 extension/shared/skills/<type>/SKILL.md。
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================== */
/* argument-type (CWE-686)                                                   */
/* ======================================================================== */

static void p17_sink_u32(uint32_t *p) { (void)p; }
static void p17_sink_u64(uint64_t *p) { (void)p; }
static void p17_sink_void(void *p) { (void)p; }

void p17_argtype_bool_to_u32(void) {
    bool flag = true;
    p17_sink_u32((uint32_t *)&flag); /* finding: 1-byte bool read as 4-byte uint32 */
}

void p17_argtype_u32_to_u64(void) {
    uint32_t n = 0;
    p17_sink_u64((uint64_t *)&n); /* finding: 4-byte uint32 read as 8-byte uint64 */
}

void p17_argtype_same_size_int(void) {
    int32_t n = 0;
    p17_sink_u32((uint32_t *)&n); /* no_finding: int32/uint32 same-size reinterpretation */
}

void p17_argtype_void_boundary(void) {
    bool flag = false;
    p17_sink_void((uint32_t *)&flag); /* no_finding: void* is a legal generic boundary */
}

/* ======================================================================== */
/* data-representation (CWE-843)                                             */
/* ======================================================================== */

static int p17_cmp_ptr(const void *a, const void *b) {
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    return strcmp(sa, sb);
}

static int p17_cmp_scalar(const void *a, const void *b) {
    unsigned char ca = *(const unsigned char *)a;
    unsigned char cb = *(const unsigned char *)b;
    return (ca > cb) - (ca < cb);
}

void p17_datarep_qsort_char(void) {
    char buf[8] = "dcba";
    qsort(buf, 4, sizeof(char), p17_cmp_ptr); /* finding: char elements read as char* */
}

void p17_datarep_bsearch_char(void) {
    char buf[8] = "dcba";
    const char *needle = "a";
    bsearch(needle, buf, 4, sizeof(char), p17_cmp_ptr); /* finding: bsearch base elements are char */
}

void p17_datarep_ptr_array(void) {
    char *arr[4] = {"a", "b", "c", "d"};
    qsort(arr, 4, sizeof(char *), p17_cmp_ptr); /* no_finding: elements ARE char* */
}

void p17_datarep_scalar_cmp(void) {
    char buf[8] = "dcba";
    qsort(buf, 4, sizeof(char), p17_cmp_scalar); /* no_finding: scalar comparator matches */
}

/* ======================================================================== */
/* implicit-contract (CWE-20)                                                */
/* ======================================================================== */

typedef struct p17_node {
    int value;
} p17_node_t;

typedef struct p17_resp {
    p17_node_t *group_data;
    unsigned    group_num;
    int         flag;
} p17_resp_t;

int p17_contract_partial_guard(p17_resp_t *resp) {
    p17_node_t *tree = resp->group_data;
    if (resp->flag != 0) {
        if (tree == NULL) {
            return -1;
        }
        return tree->value;
    }
    for (unsigned i = 0; i < resp->group_num; i++) {
        tree[i].value = 0; /* finding: unguarded deref on the flag == 0 path */
    }
    return 0;
}

int p17_contract_direct_counted(p17_resp_t *resp) {
    if (resp->flag != 0) {
        if (resp->group_data == NULL) {
            return -1;
        }
    }
    for (unsigned i = 0; i < resp->group_num; i++) {
        resp->group_data[i].value = 0; /* finding: direct field subscript, partial guard */
    }
    return 0;
}

int p17_contract_fully_guarded(p17_resp_t *resp) {
    p17_node_t *tree = resp->group_data;
    if (tree == NULL) {
        return -1;
    }
    for (unsigned i = 0; i < resp->group_num; i++) {
        tree[i].value = 0; /* no_finding: the null guard dominates this deref */
    }
    return 0;
}

int p17_contract_written_in_scope(p17_resp_t *resp) {
    p17_node_t local_node;
    local_node.value = 0;
    resp->group_data = &local_node;
    for (unsigned i = 0; i < resp->group_num; i++) {
        resp->group_data[i].value = 0; /* no_finding: the field is function-controlled */
    }
    return 0;
}
