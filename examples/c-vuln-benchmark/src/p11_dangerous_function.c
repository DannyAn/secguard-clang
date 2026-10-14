/*
 * Phase 11 — dangerous-function (CWE-676) 覆盖缺口补全 + 分层策略扩展。
 *
 * 检测能力：调用被禁/非安全的函数本身就是缺陷 —— 这是 POLICY 检查，与上下文
 * 无关（dest 是否被 bounds check 保护不影响判定）。Detector 对内置策略表做一次
 * 整树 call_expression 匹配，命中即按 category 产出事件；planner 默认判 confirmed
 * （assert_usage 交 AI → suspected）。
 *
 * 用例：
 *   DGF-01..14  expect=finding   （各 category 名单命中）
 *   DGF-15      expect=no_finding（等价的安全 _s 替代集群）
 *   DGF-16      expect=no_finding（main 内 exit 允许）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <setjmp.h>
#include <sys/socket.h>


static char g_dst[128];
static char g_src[128];
static jmp_buf g_env;


void dgf_read_line(void) {
    gets(g_dst);
}

void dgf_temp_file(void) {
    char tmpl[] = "/tmp/appXXXXXX";
    char *path = mktemp(tmpl);
    if (path) {
        printf("tmp: %s\n", path);
    }
}

void dgf_resolve_host(void) {
    struct hostent *he = gethostbyname("localhost");
    if (he) {
        printf("resolved\n");
    }
}

void dgf_memory(void) {
    memcpy(g_dst, g_src, 8);
}

void dgf_string(void) {
    strcpy(g_dst, g_src);
}

void dgf_format(void) {
    sprintf(g_dst, "%s", g_src);
}

void dgf_scan(void) {
    int v = 0;
    sscanf(g_src, "%d", &v);
}

void dgf_convert(void) {
    (void)atoi(g_src);
}

void dgf_kill(void) {
    abort();
}

void dgf_stack(void) {
    char *p = alloca(64);
    (void)p;
}

void dgf_jump(void) {
    if (setjmp(g_env) == 0) {
        longjmp(g_env, 1);
    }
}

void dgf_grow(void) {
    void *p = realloc(NULL, 8);
    (void)p;
}


void dgf_safe_replacements(void) {
    char tmpl[] = "/tmp/appXXXXXX";
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int fd;

    memset_s(g_dst, sizeof(g_dst), 0, sizeof(g_dst));
    memcpy_s(g_dst, sizeof(g_dst), g_src, 8);
    strcpy_s(g_dst, sizeof(g_dst), g_src);
    snprintf_s(g_dst, sizeof(g_dst), sizeof(g_dst), "%s", g_src);
    sprintf_s(g_dst, sizeof(g_dst), "%s", g_src);

    if (!fgets(g_src, sizeof(g_src), stdin)) {
        return;
    }

    memset_s(&hints, sizeof(hints), 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo("localhost", NULL, &hints, &res) == 0 && res) {
        freeaddrinfo(res);
    }

    fd = mkstemp(tmpl);
    if (fd >= 0) {
        close(fd);
    }

    printf("%s", g_dst);
}

int main(void) {
    dgf_read_line();
    dgf_temp_file();
    dgf_resolve_host();
    dgf_memory();
    dgf_string();
    dgf_format();
    dgf_scan();
    dgf_convert();
    dgf_kill();
    dgf_stack();
    dgf_jump();
    dgf_grow();
    dgf_safe_replacements();
    exit(0);
    return 0;
}
