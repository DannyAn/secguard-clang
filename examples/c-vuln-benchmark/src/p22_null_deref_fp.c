/*
 * Phase 22 — null-deref (CWE-476) 三类误报修复回归防线。
 *
 * 生产环境 AI 复核报告 null-deref 候选 6 项误报，三个根因与对应修复：
 *
 * 1. R1 短路保护：callee 守卫条件行上的解引用（`p == NULL || !p->field`、
 *    `p == NULL || p[0] == '\0'`）由短路求值保护——右操作数仅在 p 非空时
 *    求值。interprocedural 检测器不再把该参数判为 unguarded，调用点不再
 *    合成 DEREFERENCE 事件。
 * 2. R2 条件非空 getter：callee 仅在参数 NULL 检查下返回 NULL、其余路径
 *    返回 address-of（永不为 NULL）。调用点处于实参自身的判空守卫内
 *    （实参无 reaching null source）→ 候选消除。
 * 3. R3 守卫互斥：strip 类函数 NULL 路径 = 入参 NULL 检查 + strlen 溢出
 *    检查，成功路径转发参数。调用点实参已证非空（参数 NULL 路径不可达）
 *    且合取守卫 `strlen(arg) != 0 && lhs == NULL` 早退——溢出蕴含
 *    strlen(arg) >= len > 0 即 strlen(arg) != 0，守卫必先命中 → 残余路径
 *    lhs 非空 → 候选消除。
 *
 * 真阳性控制组（防止为降误报而整体关停或过度放宽）：
 *   - id 范围 getter（NULL 依赖 id 越界而非参数 null 检查）无守卫消费必须报；
 *   - 全局状态 getter（无参数）相邻函数判空不一致必须报；
 *   - 布尔分支绕过判空守卫（is_all 时守卫失效）必须报。
 *
 * 用例：
 *   P22-01 expect=no_finding  R1：`p == NULL || !p->field` 短路守卫调用点
 *   P22-02 expect=no_finding  R2：实参判空守卫内调用条件非空 getter
 *   P22-03 expect=no_finding  R3：strip + strlen 合取守卫互斥
 *   P22-04 expect=finding     TP-1：范围 getter 无守卫消费
 *   P22-05 expect=finding     TP-2：全局 getter 相邻函数判空不一致
 *   P22-06 expect=finding     TP-3：布尔分支绕过判空守卫
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int is_used;
    unsigned int value;
} idm_record_t;

typedef struct {
    unsigned int ipv4;
} server_addr_t;

typedef struct {
    int id;
    server_addr_t addr;
} client_info_t;

unsigned int idm_get_import_result(const idm_record_t *record)
{
    if (record == NULL || !record->is_used) {
        return 0xFFFFFFFFu;
    }
    return record->value;
}

int idm_custom_portal_delete_unused_image(const char *file_name)
{
    if (file_name == NULL || file_name[0] == '\0') {
        return 0;
    }
    return 1;
}

server_addr_t *get_server_addr(client_info_t *client)
{
    if (client == NULL) {
        return NULL;
    }
    return &client->addr;
}

static char *strip(const char *in, char *buf, size_t len)
{
    if (in == NULL || buf == NULL) {
        return NULL;
    }
    if (strlen(in) >= len) {
        return NULL;
    }
    strcpy(buf, in);
    return buf;
}

#define MAX_IP 1024u

typedef struct {
    unsigned char ipv6[16];
} ip_rec_t;

static ip_rec_t g_table[MAX_IP];

ip_rec_t *find_ip_record(unsigned int id)
{
    if (id >= MAX_IP) {
        return NULL;
    }
    return &g_table[id];
}

static server_addr_t g_addr;
static int g_loaded;

server_addr_t *get_config_addr(void)
{
    if (!g_loaded) {
        return NULL;
    }
    return &g_addr;
}

static char g_user_name[32];
static int g_has_user;

const char *get_user_name(void)
{
    if (!g_has_user) {
        return NULL;
    }
    return g_user_name;
}

int caller_import_result(void)
{
    idm_record_t *rec = malloc(sizeof *rec);
    const char *name = (const char *)malloc(8);

    unsigned int result = idm_get_import_result(rec);
    int kept = idm_custom_portal_delete_unused_image(name);
    free(rec);
    free((void *)name);
    return (int)result + kept;
}

unsigned int caller_checked_getter(client_info_t *client)
{
    if (client == NULL) {
        return 0;
    }
    server_addr_t *addr = get_server_addr(client);
    return addr->ipv4;
}

int caller_strip_checked(const char *user_name)
{
    char buf[64];

    if (user_name == NULL) {
        return -1;
    }
    char *real_name = strip(user_name, buf, sizeof(buf));
    if (strlen(user_name) != 0 && real_name == NULL) {
        return -1;
    }
    return real_name[0] != '\0';
}

void idm_ip_cmp(unsigned int id)
{
    ip_rec_t *lhs = find_ip_record(id);
    lhs->ipv6[0] = 1;
}

static void sibling_checked(void)
{
    server_addr_t *a = get_config_addr();
    if (a != NULL) {
        a->ipv4 = 1;
    }
}

static void sibling_unchecked(void)
{
    server_addr_t *b = get_config_addr();
    b->ipv4 = 2;
}

void process_user_list(int is_all)
{
    const char *usr_name = get_user_name();

    if (!is_all && usr_name == NULL) {
        return;
    }
    if (usr_name[0] == 'a') {
        printf("admin user\n");
    }
}

int main(void)
{
    client_info_t cli;

    caller_import_result();
    caller_checked_getter(&cli);
    caller_strip_checked("admin");
    idm_ip_cmp(3);
    g_loaded = 1;
    sibling_checked();
    sibling_unchecked();
    g_has_user = 1;
    process_user_list(0);
    return 0;
}