/*
 * Phase 11 — 反证 / FP 守卫（expect=no_finding）补全。
 *
 * 这批用例补齐四个类型缺失的「不该报」防线：deadlock / hardcoded-secret /
 * out-of-bounds / use-after-free。基准的意图是误报消减，只有每个类型都同时有
 * 「该报」与「不该报」的对照，检测能力才算被完整锁定。
 *
 * 注意 deadlock 的构造：LockOrderFilter 用**全局**锁序图（跨文件同一锁名共享节点）
 * 找强连通分量，且 fail-open —— 非环候选仍以 suspected 保留，永不丢弃。因此本文件的
 * 两把锁必须「只按同一顺序获取」（任何地方都不出现反向获取），才会根本不产出事件。
 *
 * 用例：
 *   DL-01          expect=no_finding  两线程锁序一致，锁序图无环
 *   HS-01          expect=no_finding  凭据来自环境变量，非字面量
 *   OOB-02         expect=no_finding  索引严格小于数组长度
 *   UAF-01         expect=no_finding  free 后重新分配，再使用新块
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static pthread_mutex_t g_guard_theta = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_guard_phi = PTHREAD_MUTEX_INITIALIZER;


static void *dl_consistent_order_1(void *arg) {
    (void)arg;

    pthread_mutex_lock(&g_guard_theta);
    pthread_mutex_lock(&g_guard_phi);
    pthread_mutex_unlock(&g_guard_phi);
    pthread_mutex_unlock(&g_guard_theta);
    return NULL;
}


static void *dl_consistent_order_2(void *arg) {
    (void)arg;

    pthread_mutex_lock(&g_guard_theta);
    pthread_mutex_lock(&g_guard_phi);
    pthread_mutex_unlock(&g_guard_phi);
    pthread_mutex_unlock(&g_guard_theta);
    return NULL;
}


const char *hs_credential_from_env(void) {
    const char *db_password = getenv("APP_DB_PASSWORD");

    if (!db_password) {
        return "";
    }
    return db_password;
}


int oob_sum_bounded(void) {
    int samples[10];
    int total = 0;

    memset(samples, 0, sizeof(samples));
    for (int i = 0; i < 10; i++) {
        total += samples[i];
    }
    return total;
}


void uaf_use_after_realloc(void) {
    char *payload = (char *)malloc(32);

    if (!payload) {
        return;
    }

    free(payload);

    payload = (char *)malloc(32);
    if (!payload) {
        return;
    }

    memset(payload, 0, 32);
    free(payload);
}

int main(void) {
    dl_consistent_order_1(NULL);
    dl_consistent_order_2(NULL);
    (void)hs_credential_from_env();
    (void)oob_sum_bounded();
    uaf_use_after_realloc();
    return 0;
}
