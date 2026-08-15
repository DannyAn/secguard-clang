/*
 * P4 — uninit (VALUE_USE) 收敛用例
 *
 * 锁定 zlib 生产环境暴露并已修复的缺陷场景：
 *   1. struct_partial_uninit 字段 key 错配 bug —— 字段赋值后仍被误报
 *   2. uninit 缺少流敏感收敛 —— 新增 definite_init 过滤器
 * 以及召回（漏报）场景，防止收敛/检测器过猛：
 *   3. 单行 while 的行号碰撞（过滤器把 body 的 copy 误用到 header）
 *   4. 复制未初始化（init_declarator 把 RHS 读取误记为赋值）
 */

#include <stdlib.h>

typedef struct Point { int x; int y; } Point;

/* 真阳性：声明未初始化即使用（应报告 finding） */
int tp_uninit_use(void) {
    int a;
    return a + 1;
}

/* 误报：结构体字段已赋值，不应报 struct_partial_uninit（key 错配 bug） */
int fp_struct_field_init(void) {
    Point p;
    p.x = 1;
    p.y = 2;
    return p.x + p.y;
}

/* 真阳性：单行 while 循环可能不执行，x 在 n<=0 路径未初始化（行号碰撞 bug） */
int tp_while_single_line(int n) {
    int x;
    while (n > 0) { x = n; n--; }
    return x;
}

/* 真阳性：复制未初始化（int b = a 读取未初始化的 a） */
int tp_copy_uninit(void) {
    int a;
    int b = a;
    return b;
}
