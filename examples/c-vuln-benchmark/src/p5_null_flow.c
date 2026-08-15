/*
 * P5 — null-deref 流敏感收敛用例
 *
 * 锁定 null-deref 流敏感过滤器（nullable_source）的两个场景：
 *   - 重赋值杀空：malloc 之后被确定非空值覆盖（&x）
 *   - 守卫兜底：NULL 守卫内用字符串字面量兜底
 * 以及一个真阳性对照。
 */

#include <stdlib.h>

typedef struct Node { int value; } Node;

static Node g_fallback;

/* 真阳性：malloc 结果未检查即解引用（应报告 finding） */
int tp_unchecked_malloc(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    return p->value;
}

/* 误报：malloc 之后被 &g_fallback 重赋值（确定非空），不应报 */
int fp_reassign_addressof(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    p = &g_fallback;
    return p->value;
}

/* 误报：NULL 守卫内用字符串字面量兜底，不应报 */
int fp_guard_default_literal(void) {
    const char *p = getenv("HOME");
    if (p == NULL) {
        p = "";
    }
    return p[0];
}
