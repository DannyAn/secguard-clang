/*
 * Phase 6 — resource-leak (CWE-404) 典型用例
 *
 * 三类构成：
 *   - RL-01 ~ RL-06  真泄漏，当前 0.6.0 应检出 → 回归防线
 *   - RL-07 ~ RL-09  正确安全形态，应保持静默 → 防 FP 回潮
 *   - RL-10 ~ RL-12  已确认检测缺口，期望 finding 但当前漏报
 *     （validator 现阶段对这三个报 FN 属预期结果，作为缺陷修复的
 *      回归目标；修复后 recall 应上升，见 benchmark.md Phase 6 节）
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <sqlite3.h>

/* ── 真泄漏：当前应检出（expect: finding）────────────────────────── */

/* RL-01: fopen 错误路径 return，正常路径无 fclose */
int rl01_fopen_leak(void) {
    FILE *f = fopen("/tmp/rl01.log", "w");
    if (f == NULL) {
        return -1;
    }
    fprintf(f, "hello\n");
    return 0;
}

/* RL-02: open 错误路径 return -1，正常路径无 close */
int rl02_open_leak(void) {
    int fd = open("/tmp/rl02.txt", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    char buf[16];
    read(fd, buf, sizeof(buf));
    return 0;
}

/* RL-03: socket + connect 失败路径未 close（connect 是错误码不是资源） */
int rl03_socket_connect_leak(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return -1;
    }
    if (connect(s, 0, 0) != 0) {
        return -1;
    }
    return 0;
}

/* RL-04: epoll_create1 无 close（fd 工厂回归防线） */
int rl04_epoll_leak(void) {
    int ep = epoll_create1(0);
    if (ep < 0) {
        return -1;
    }
    return 0;
}

/* RL-05: mutex_lock 后无 unlock（锁泄漏） */
void rl05_lock_leak(void) {
    pthread_mutex_t m;
    pthread_mutex_init(&m, 0);
    pthread_mutex_lock(&m);
    do_work_rl();
}

/* RL-06: 条件释放 —— fclose 只在 if 分支内，其余路径泄漏（流敏感） */
void rl06_conditional_close_leak(int flag) {
    FILE *f = fopen("/tmp/rl06.log", "r");
    if (f == NULL) {
        return;
    }
    if (flag) {
        fclose(f);
    }
}

/* ── 安全形态：应保持静默（expect: no_finding）──────────────────── */

/* RL-07: fopen 后 fclose */
void rl07_fopen_close_ok(void) {
    FILE *f = fopen("/tmp/rl07.log", "w");
    if (f != NULL) {
        fclose(f);
    }
}

/* RL-08: 资源 return 给 caller（所有权转移） */
FILE *rl08_transfer_ok(void) {
    FILE *f = fopen("/tmp/rl08.log", "a");
    if (f == NULL) {
        return NULL;
    }
    return f;
}

/* RL-09: open 检查 + 正常 close */
int rl09_checked_close_ok(void) {
    int fd = open("/tmp/rl09.txt", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

/* ── 已确认缺口：期望 finding，当前漏报（缺陷回归目标）──────────── */

/* RL-10 [known-gap]: 错误路径 `return fd` 被误判为所有权转移，
 * 正常路径忘 close 未检出。根因：isReturnedToCaller + graph
 * OWNERSHIP_TRANSFER 双层把 `return fd`（此时 fd 为 -1 错误码）
 * 当作真转移。修复目标用例。 */
int rl10_error_return_masks_leak(void) {
    int fd = open("/tmp/rl10.txt", O_RDONLY);
    if (fd < 0) {
        return fd;
    }
    write(fd, "x", 1);
    return 0;
}

/* RL-11 [known-gap]: dup 是 fd 工厂但不在 isResourceAcquirer
 * 白名单（dup/dup2/pipe/socketpair/mkstemp 同类），acquire 未识别。 */
int rl11_dup_leak(void) {
    int d = dup(STDOUT_FILENO);
    if (d < 0) {
        return -1;
    }
    return 0;
}

/* RL-12 [known-gap]: out-param 型 acquirer —— sqlite3_open 的资源
 * 写入 &db 而非返回值，findAcquires 只扫赋值 RHS，形态不识别
 * （fopen_s/RegCreateKeyEx 同类）。 */
int rl12_outparam_open_leak(void) {
    sqlite3 *db;
    if (sqlite3_open("/tmp/rl12.db", &db) != SQLITE_OK) {
        return -1;
    }
    sqlite3_exec(db, "SELECT 1", NULL, NULL, NULL);
    return 0;
}

/* ── 缺陷修复补充：白名单边界成员（返回值型 / out-param 型）──────── */

/* RL-13: mkstemp 泄漏（长名子串匹配的 fd 工厂，返回值型） */
int rl13_mkstemp_leak(void) {
    char tmpl[] = "/tmp/rl13-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        return -1;
    }
    return 0;
}

/* RL-14: fopen_s out-param 泄漏（out-param 型 acquirer 白名单另一成员） */
int rl14_fopen_s_leak(void) {
    FILE *f = NULL;
    if (fopen_s(&f, "/tmp/rl14.log", "w") != 0) {
        return -1;
    }
    return 0;
}

void do_work_rl(void) {
    (void)0;
}