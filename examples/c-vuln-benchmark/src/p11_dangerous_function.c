/*
 * Phase 11 — dangerous-function (CWE-676) 覆盖缺口补全。
 *
 * 检测能力：调用被禁 / 已过时的 libc 函数本身就是缺陷 —— 这是 POLICY 检查，
 * 与上下文无关（dest 是否被 bounds check 保护不影响判定）。Detector 对内置
 * 名单做一次整树 call_expression 匹配，命中即产出事件，planner 默认判定
 * confirmed（无需 AI 研判）。
 *
 * 用例：
 *   DGF-01..03  expect=finding   （gets / mktemp / gethostbyname 名单命中）
 *   DGF-04      expect=no_finding（等价的安全替代，不在名单内）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>


void dgf_read_line(void) {
    char buf[128];

    gets(buf);
    printf("%s", buf);
}


void dgf_temp_file(void) {
    char tmpl[] = "/tmp/appXXXXXX";

    char *path = mktemp(tmpl);
    if (path) {
        printf("tmp: %s\n", path);
    }
}


void dgf_resolve_host(const char *host) {
    struct hostent *he = gethostbyname(host);

    if (he) {
        printf("resolved\n");
    }
}


void dgf_safe_replacements(const char *host) {
    char buf[128];
    char tmpl[] = "/tmp/appXXXXXX";
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int fd;

    if (!fgets(buf, sizeof(buf), stdin)) {
        return;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
        freeaddrinfo(res);
    }

    fd = mkstemp(tmpl);
    if (fd >= 0) {
        close(fd);
    }

    memmove(buf, "safe", 4);
    printf("%s", buf);
}

int main(void) {
    dgf_read_line();
    dgf_temp_file();
    dgf_resolve_host("localhost");
    dgf_safe_replacements("localhost");
    return 0;
}
