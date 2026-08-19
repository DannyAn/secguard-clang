/*
 * P10 — 1-CFA 过程间上下文敏感（形参敏感摘要）用例
 *
 * 锁定跨函数污点传播的上下文敏感分析：
 *   - 形参 passthrough：id(s) 返回形参，id(getenv) 传播污点、id("literal") 不传播
 *   - 多级 passthrough：wrap2(s){return id(s);} 跨函数归纳
 *   - 链式形参污点：main → A → B → C 跨多跳传播到最终 sink
 */

#include <stdlib.h>
#include <stdio.h>

char *id(char *s) {
    return s;
}

char *wrap2(char *s) {
    return id(s);
}

/* 真阳性：id(getenv) 经形参 passthrough 传播污点（应报告 finding） */
int tp_passthrough_taint(void) {
    char *p = id(getenv("CMD"));
    FILE *f = fopen(p, "r");
    return f != 0;
}

/* 误报：id("literal") 字面量不传播污点（应抑制） */
int fp_passthrough_literal(void) {
    char *p = id("/tmp/x");
    FILE *f = fopen(p, "r");
    return f != 0;
}

/* 真阳性：wrap2(getenv) 多级 passthrough 传播污点（应报告 finding） */
int tp_multilevel_passthrough(void) {
    char *p = wrap2(getenv("CMD"));
    FILE *f = fopen(p, "r");
    return f != 0;
}

/* ── 链式形参污点：main → A → B → C ─────────────────────────────── */

void C(char *s) {
    char *cmd = s;
    system(cmd);
}

void B(char *s) {
    C(s);
}

void A(char *s) {
    B(s);
}

/* 真阳性：污点经 A→B→C 到达 C 的局部 sink（应报告 finding） */
void tp_transitive_param(void) {
    char *input = getenv("CMD");
    A(input);
}
