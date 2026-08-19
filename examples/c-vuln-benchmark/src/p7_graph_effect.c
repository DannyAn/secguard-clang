/*
 * P7 — 语义图真实生效用例（semantic graph 被收敛管线消费，而非仅构建）
 *
 * 锁定收敛管线对语义图的真实消费：
 *   - 污点 source→sink：taint_source 过滤器消费 DATA_FLOW + PARAM_BINDING/RETURN 边
 *   - 生命周期 free→use：lifetime 过滤器消费语句级 CFG 可达性
 *   - 别名传播：use-after-free 经 ALIAS 边（q=p）发现悬空别名
 *   - 所有权转移：OWNERSHIP_TRANSFER（store-to-global）不算泄漏
 */

#include <stdlib.h>
#include <stdio.h>

/* ── 污点 source→sink ───────────────────────────────────────────── */

/* 真阳性：getenv 污点流向 fopen 路径参数（应报告 finding） */
int tp_tainted_path(void) {
    char *path = getenv("HOME");
    FILE *f = fopen(path, "r");
    return f != 0;
}

/* 误报：字面量路径，无污点源可达（应抑制） */
int fp_literal_path(void) {
    char buf[64] = "/tmp/log.txt";
    FILE *f = fopen(buf, "r");
    return f != 0;
}

/* ── 生命周期 free→use（语句级 CFG 可达性） ─────────────────────── */

/* 真阳性：free 与 use 在同一条路径上（应报告 finding） */
int tp_uaf_same_path(void) {
    char *p = malloc(32);
    free(p);
    return p[0];
}

/* 误报：free 与 use 在互斥分支上不可达（应抑制） */
int fp_uaf_exclusive_branch(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        return 0;
    }
    return p[0];
}

/* ── 别名传播（q=p 后 free(p) 使 q 悬空） ─────────────────────────── */

/* 真阳性：q 是 p 的别名，free(p) 后解引用 *q（应报告 finding） */
int tp_uaf_alias(void) {
    char *p = malloc(32);
    char *q = p;
    free(p);
    return q[0];
}

/* ── 所有权转移（store-to-global 不算泄漏） ──────────────────────── */

static char *g_escape;

/* 真阳性：malloc 未释放（应报告 finding） */
int tp_leak_no_free(void) {
    char *p = malloc(64);
    return p[0];
}

/* 误报：malloc 存到全局，所有权逃逸，不算泄漏（应抑制） */
int fp_leak_escaped_global(void) {
    char *p = malloc(64);
    g_escape = p;
    return 0;
}
