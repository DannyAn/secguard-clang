/*
 * Phase 11 — format-string (CWE-134) 覆盖缺口补全。
 *
 * 检测能力：printf 族（printf/fprintf/sprintf/snprintf/syslog/...）以**非字面量**
 * 作为格式串。Detector 只看格式实参是否为字符串字面量；planner 再经
 * TaintSourceFilter + 调用点普查（call-site census）判定外部可控性 ——
 * 非 static 函数形参按"树内调用点实参形态"定夺：
 *   - 树内调用点全部传编译期常量且未被取地址 → pipeline gate drop
 *   - 存在变量/污点调用点 → 保留，AI 按 callsites@ census 研判
 *
 * 用例：
 *   FS-01..03  expect=no_finding（格式串形参，但树内唯一调用点传字面量 ——
 *              封闭程序内不可利用；P1 语义前为 finding，依赖已被推翻的保守播种）
 *   FS-04      expect=no_finding（格式串为字面量，值走 %s 参数化输出）
 */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>


void fs_log_user_message(const char *user_msg) {
    if (!user_msg) {
        return;
    }

    printf(user_msg);
}


void fs_log_to_stream(FILE *log, const char *fmt) {
    if (!log || !fmt) {
        return;
    }

    fprintf(log, fmt);
}


void fs_syslog_message(const char *msg) {
    if (!msg) {
        return;
    }

    syslog(LOG_ERR, msg);
}


void fs_log_safe(const char *user_msg) {
    if (!user_msg) {
        return;
    }

    printf("%s", user_msg);
    fprintf(stderr, "[INFO] %s\n", user_msg);
}

int main(void) {
    fs_log_user_message("hello");
    fs_log_to_stream(stderr, "hello %s\n");
    fs_syslog_message("hello");
    fs_log_safe("hello");
    return 0;
}
