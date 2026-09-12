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

/* 误报：malloc 之后被 &g_fallback 重赋值（确定非空），不应报 null-deref。
 * 先 free 再重赋值，否则 malloc 块被覆盖而泄漏（memory-leak 真阳性）。 */
int fp_reassign_addressof(void) {
    Node *p = (Node *)malloc(sizeof(Node));

    free(p);
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

/* 误报：a = b 拷贝传播，b 已是确定非空的地址 —— 不应报 null-deref。
 * 先 free 再拷贝，否则 a 的 malloc 块被覆盖而泄漏（memory-leak 真阳性）。
 * （迁移自 examples/nullflow-demo/src/demo.c 的 fp_copy_nonnull） */
int fp_copy_nonnull(void) {
    Node *a = (Node *)malloc(sizeof(Node));
    Node *b = &g_fallback;

    free(a);
    a = b;
    return a->value;
}

/* 误报：解引用位于 return 之后的不可达代码 —— 不应报 null-deref。
 * 提前 free，否则 malloc 块在 return 后泄漏（memory-leak 真阳性）。
 * （迁移自 examples/nullflow-demo/src/demo.c 的 fp_dead_after_return） */
int fp_dead_after_return(void) {
    Node *p = (Node *)malloc(sizeof(Node));

    free(p);
    return 0;
    p->value = 1;
    return 2;
}
