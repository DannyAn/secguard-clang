/*
 * Phase 11 — signal-handler (CWE-479) 覆盖缺口补全。
 *
 * 检测能力：经 signal(2) 注册的信号处理器体内**直接**调用了不在 POSIX
 * async-signal-safe 列表内的 libc 函数（printf/malloc/free/pthread_mutex_lock...）。
 * 该集合是固定且权威的，所以直接调用即是确定缺陷，planner 默认判定 confirmed。
 * 传递调用（handler -> helper -> malloc）与 sigaction 注册刻意不在范围内。
 *
 * 用例：
 *   SH-01..02  expect=finding   （处理器内 printf / malloc+free）
 *   SH-03..04  expect=no_finding（只写 sig_atomic_t；只用 write/_exit）
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t g_shutdown = 0;


static void sh_unsafe_log_handler(int sig) {
    printf("signal %d caught\n", sig);
}


static void sh_unsafe_alloc_handler(int sig) {
    char *scratch = (char *)malloc(64);

    (void)sig;
    if (!scratch) {
        return;
    }
    free(scratch);
}


static void sh_safe_flag_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}


static void sh_safe_write_handler(int sig) {
    static const char msg[] = "signal caught\n";
    ssize_t written = write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    if (written < 0) {
        return;
    }
    if (sig == SIGTERM) {
        _exit(0);
    }
}

void sh_install_handlers(void) {
    signal(SIGINT, sh_unsafe_log_handler);
    signal(SIGUSR1, sh_unsafe_alloc_handler);
    signal(SIGTERM, sh_safe_flag_handler);
    signal(SIGHUP, sh_safe_write_handler);
}

int main(void) {
    sh_install_handlers();
    return g_shutdown;
}
