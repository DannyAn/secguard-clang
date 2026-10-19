/*
 * Phase 18 — P1 call-site census 回归防线。
 *
 * 语义（P1 起）：非 static 函数的形参 sink 不再无条件保守保留。planner 对每个
 * (callee, param) 做树内调用点实参普查（callsite census）：
 *   - 树内调用点全部传编译期常量且函数未被取地址 → pipeline gate drop
 *   - 存在变量/污点调用点 → candidate 保留，AI 按 callsites@ census 研判
 *   - basename / strrchr(p, '/') 派生的路径段 → path-traversal 净化 kill
 * 用例：
 *   CS-01 expect=no_finding  format wrapper 非 static，树内调用点全字面量（gate drop）
 *   CS-02 expect=finding     format wrapper 存在污点调用点（census 保留 + taint promote）
 *   CS-03 expect=no_finding  fopen(basename(user)) —— 净化 kill
 *   CS-04 expect=no_finding  fopen(strrchr(user, '/') + 1) —— 净化 kill
 *   CS-05 expect=no_finding  path wrapper 非 static，树内调用点全字面量（gate drop）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>


void cs_log_wrapper(const char *fmt) {
    if (!fmt) return;
    printf(fmt);
}


void cs_log_var(const char *fmt) {
    if (!fmt) return;
    printf(fmt);
}


void cs_open_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}


void cs_handle_user_path(const char *user_path) {
    char *base = basename((char *)user_path);
    char *seg = strrchr(user_path, '/');
    FILE *f1 = fopen(base, "r");
    if (f1) fclose(f1);
    if (seg) {
        FILE *f2 = fopen(seg + 1, "r");
        if (f2) fclose(f2);
    }
}
}

int main(int argc, char **argv) {
    cs_log_wrapper("startup");
    cs_log_wrapper("shutdown");
    cs_log_var("boot");
    cs_log_var(getenv("LOG_FMT"));
    cs_open_config("/etc/app.cfg");
    if (argc > 1) {
        cs_handle_user_path(argv[1]);
    }
    return 0;
}