/*
 * Phase 30 — cross-function return-alias double-free (CWE-415) 覆盖缺口。
 *
 * make_ptr 无条件 free(p) 后返回悬空 p；caller 里 q = make_ptr() 拿到同一个
 * 悬空对象，再 free(q) 就是同一对象的第二次释放 —— 函数内视角看不到（两个 free
 * 分属两个函数，且 q 与 p 的别名关系只存在于跨函数 return 链上）。
 *
 * 已知漏报（known_gap）：detectCrossFunctionDoubleFree 未启用。AliasGraph 是
 * flow- 且 call-site-不敏感，用 return-alias 门控直接启用会引入 allocator.c 式
 * 误报（同一工厂多次调用的不同对象被合并）。启用需 call-site 敏感 + "被调函数
 * 在每条返回路径都 free 其返回值"事实，属独立 Phase。
 */
#include <stdlib.h>

void *make_ptr(void) {
    void *p = malloc(16);
    if (!p) return NULL;
    free(p);
    return p;
}

void use_ptr(void) {
    void *q = make_ptr();
    free(q);
}

int main(void) {
    use_ptr();
    return 0;
}
