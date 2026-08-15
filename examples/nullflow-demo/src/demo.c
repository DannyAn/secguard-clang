/*
 * nullflow-demo — 流敏感空指针收敛演示
 *
 * 这个样例专门演示 sgre 的 graph 机制（CFG + DATA_FLOW）如何减少流向 AI Agent
 * 的 null-deref 候选。每一处注释标注了“应保留”还是“应抑制”。
 *
 * 旧的行为（行号顺序启发式）：只要某变量在解引用之前有过一次 NULL_VALUE 来源，
 * 就保留候选，因此下面 5 个函数全部进入 AI Agent。
 *
 * 新的行为（流敏感 CFG/DFG 分析）：只有当 NULL 来源能沿控制流到达解引用点、
 * 且中途没有被“确定非空”的重赋值杀掉时才保留，因此只保留 tp_* 真阳性。
 */

#include <stdlib.h>

typedef struct Node {
    int value;
    struct Node *next;
} Node;

static Node g_fallback;

/* 真阳性：malloc 结果未检查即解引用 —— 应保留 */
int tp_unchecked_malloc(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    return p->value;
}

/* 误报：malloc 之后被 &g_fallback 重赋值（确定非空）—— 应抑制 */
int fp_reassign_addressof(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    p = &g_fallback;
    return p->value;
}

/* 误报：getenv 之后被 NULL 守卫内的字符串字面量兜底 —— 应抑制 */
int fp_guard_default_literal(void) {
    const char *p = getenv("HOME");
    if (p == NULL) {
        p = "";
    }
    return p[0];
}

/* 误报：a = b，而 b 是 &g_fallback（非空）—— 应抑制 */
int fp_copy_nonnull(void) {
    Node *a = (Node *)malloc(sizeof(Node));
    Node *b = &g_fallback;
    a = b;
    return a->value;
}

/* 误报：解引用位于 return 之后的不可达代码 —— 应抑制 */
int fp_dead_after_return(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    return 0;
    p->value = 1;
    return 2;
}
