/*
 * Null-deref return-value guard regression lock (issue #289 T6, pattern 2).
 * find_node returns NULL on an out-of-range key (return-value nullable); the
 * caller checks p == NULL before using it, so the guarded use must not be a
 * null-deref candidate. The unguarded variant must still be reported.
 */

#include <stdlib.h>

struct node {
    int field;
};

static struct node *find_node(int key)
{
    static struct node pool[4];
    if (key < 0 || key >= 4) {
        return NULL;          /* nullable 返回 */
    }
    return &pool[key];
}

void tc_nd_ret_guard(int key)
{
    struct node *p = find_node(key);   /* 赋值后先判空再使用 */
    if (p == NULL) {
        return;
    }
    p->field = 1;                      /* 不得报 null-deref */
}

void tc_nd_ret_guard_bad(int key)
{
    struct node *p = find_node(key);   /* 去掉判空：必须仍产出 null-deref 候选 */
    p->field = 1;
}
