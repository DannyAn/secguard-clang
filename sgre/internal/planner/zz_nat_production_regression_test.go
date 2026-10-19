//go:build !nosqlite

package planner

import "testing"

// NAT 生产复核（sc_2026-10-19_100105_8cac41）的四类误报根因回归：
//
//	D   divide-by-zero   `if (field != 0)` 防护未识别（字段/全局链除数）
//	B1-1 null-deref        check/prepare 函数入口判空 + 调用方判返回
//	B1-2 implicit-contract  调用点循环守卫未传播到被调函数
//	C   use-after-free    delete/clear 语义函数被误判为 free
//
// 每一条都配一个"真实缺陷仍被报"的控制函数，防止过度压制。

// DBZ-NAT-01..04: 字段/全局链除数被同一函数内的显式非零防护（!=0、真值、
// ==0 return、==0 置 1）保护，不得再报 CWE-369。
func TestNatDBZ_FieldChainGuard(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct { unsigned int total_resource; unsigned int used_resource; } show_data_t;
typedef struct { unsigned int ip_num; unsigned long total_num; unsigned long average_num; } sess_t;
typedef struct { sess_t sess; } pool_t;
typedef struct { unsigned int inst_num; } pool_bt_t;
typedef struct { unsigned int user_num; } alert_threshold_t;

extern pool_bt_t g_pool_bt;
extern alert_threshold_t g_alert_threshold;

unsigned long usage_show(show_data_t *show_data) {
    unsigned long usaged;
    if (show_data->total_resource != 0) {
        usaged = show_data->used_resource * 100 / show_data->total_resource;
    } else {
        usaged = 0;
    }
    return usaged;
}

void pool_stat(pool_t *pool) {
    if (pool->ip_num) {
        pool->sess.average_num = pool->sess.total_num / pool->ip_num;
    }
}

unsigned int pool_bind(unsigned int pool_id) {
    if (g_pool_bt.inst_num == 0) { return pool_id; }
    return (unsigned int)pool_id % g_pool_bt.inst_num;
}

unsigned int usertbl_usage(unsigned int user_num) {
    if (g_alert_threshold.user_num == 0) { return 0; }
    return user_num * 100 / g_alert_threshold.user_num;
}

unsigned int unguarded(show_data_t *show_data) {
    return show_data->used_resource / show_data->total_resource;
}
`
	result := planDivideByZero(t, src)
	for _, fn := range []string{"usage_show", "pool_stat", "pool_bind", "usertbl_usage"} {
		if c := candidateForFunc(t, result, fn); c != nil {
			t.Errorf("%s: guarded field divisor should NOT be flagged, got var=%s level=%s line=%d", fn, c.Target.Variable, c.SuspicionLevel, c.Target.Line)
		}
	}
	if c := candidateForFunc(t, result, "unguarded"); c == nil {
		t.Errorf("unguarded: unguarded field divisor must still be flagged (control)")
	}
}

// B1-1: check/prepare 函数入口 `if (group == NULL) return 错误码`，调用方
// `if (check(group, ...) != 0) return;` 之后 group 必非空。
func TestNatNullDeref_CheckFunctionGuard(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct { int id; } pool_group_t;

extern pool_group_t g_groups[8];

pool_group_t *pool_read_capture(int pool_id) {
    if (pool_id < 0) return NULL;
    return &g_groups[pool_id];
}

int nopat_nat44_prepare_allocate(pool_group_t *group, int pool_id) {
    if (group == NULL) return -1;
    return 0;
}

int caller(int pool_id) {
    pool_group_t *group = pool_read_capture(pool_id);
    if (nopat_nat44_prepare_allocate(group, pool_id) != 0) return -1;
    return group->id;
}

int unguarded_caller(int pool_id) {
    pool_group_t *group = pool_read_capture(pool_id);
    return group->id;
}
`
	got := planType(t, src, "null-deref")
	if c, ok := got["caller"]; ok {
		t.Errorf("caller should NOT be flagged (prepare null-checks group, caller guards the return), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if _, ok := got["unguarded_caller"]; !ok {
		t.Errorf("unguarded_caller must still be flagged (control)")
	}
}

// B1-2: 调用方 for 循环条件 `cur != NULL && cur->data != NULL` 已保证被调函数
// 内 `cur->data` 非空；sibling（同类型判空）触发候选后，调用方循环守卫必须压制。
func TestNatImplicitContract_CallerLoopGuard(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct { int drop_count[4]; } pkt_stat_t;
typedef struct node { pkt_stat_t *data; struct node *next; } node_t;

void stat_sum(node_t *cur) {
    pkt_stat_t *data = cur->data;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            if (data[i].drop_count[j] != 0) { (void)0; }
        }
    }
}

void stat_clear(node_t *cur) {
    if (cur->data != NULL) { (void)0; }
}

void caller(node_t *head) {
    for (node_t *cur = head; (cur != NULL) && (cur->data != NULL); cur = cur->next) {
        stat_sum(cur);
    }
}
`
	got := planType(t, src, "implicit-contract")
	if c, ok := got["stat_sum"]; ok {
		t.Errorf("stat_sum should NOT be flagged (caller loop-guards cur->data != NULL), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// C: 名字含 _delete 的"清配置"函数（体内仅 memset 清零 + 计数减一，从不 free）
// 不得被当作释放其入参字段，凭空构造 use-after-free。
func TestNatUAF_DeleteFunctionNotFree(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct { int vsys_id; int group_id; int id; char src_name[8]; } host_t;

void portrng_delete_syslog_server(int vsys_id, int group_id, int id) {
    (void)vsys_id; (void)group_id; (void)id;
}

void portrng_syslog_host_delete(const host_t *host) {
    portrng_delete_syslog_server(host->vsys_id, host->group_id, host->id);
}

int handle(host_t *msg) {
    host_t *host = msg;
    portrng_syslog_host_delete(host);
    return host->vsys_id + host->id + host->src_name[0];
}

int real_uaf(host_t *msg) {
    host_t *host = msg;
    free(host);
    return host->vsys_id;
}
`
	got := planType(t, src, "use-after-free")
	if c, ok := got["handle"]; ok {
		t.Errorf("handle should NOT be flagged (delete only clears config, never frees), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if _, ok := got["real_uaf"]; !ok {
		t.Errorf("real_uaf must still be flagged (control)")
	}
}

// E: vprintf 风格可变参包装 API 的 fmt 形参（转发给 vsnprintf/vsnprintf_s），
// 当树内调用点全部传字面量格式串时，fmt 不是攻击者可控的注入点。
func TestNatFormatString_VprintfWrapper(t *testing.T) {
	src := `#include <stdio.h>
#include <stdarg.h>

int str_buf_fmt_v(char *buf, unsigned int max_size, const char *fmt, va_list args) {
    return vsnprintf(buf, max_size, fmt, args);
}

void caller_a(char *buf, unsigned int size) {
    va_list ap;
    str_buf_fmt_v(buf, size, "count=%d", ap);
}

void caller_b(char *buf, unsigned int size) {
    va_list ap;
    str_buf_fmt_v(buf, size, "total=%u", ap);
}
`
	result := setupCallsiteFixture(t, src, "format-string")
	if _, ok := candidatesByFunc(result)["str_buf_fmt_v"]; ok {
		t.Errorf("str_buf_fmt_v (all callers pass literal fmt) should be dropped, got %v", candidateNames(result))
	}
}

// A: POOL_FOR_SECT 迭代器宏在 for-init 赋值、循环条件判空，循环体内解引用安全。
func TestNatNullDeref_PoolForSectIterMacro(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct sect { int id; struct sect *next; } sect_t;

#define POOL_FOR_SECT(group, sect) \
    for ((sect) = pool_first_sect(group); (sect) != NULL; (sect) = pool_next_sect(sect))

sect_t *pool_first_sect(int group);
sect_t *pool_next_sect(sect_t *sect);

int display(int group) {
    sect_t *sect = NULL;
    POOL_FOR_SECT(group, sect) {
        if (sect->id == group) { return 1; }
    }
    return 0;
}

int real_bug(int group) {
    sect_t *sect = NULL;
    return sect->id;
}
`
	got := planType(t, src, "null-deref")
	if c, ok := got["display"]; ok {
		t.Errorf("display should NOT be flagged (POOL_FOR_SECT null-guards sect), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if _, ok := got["real_bug"]; !ok {
		t.Errorf("real_bug must still be flagged (control)")
	}
}

// §3.1（第二轮生产复核）: POOL_SECT 类内联函数 `return g_pool_var.sects + node_id`
// 是静态数组基址的指针运算，返回值是数组内部/尾后地址，永不可能是 NULL。
// exprReturnsNullable 此前对 binary_expression 一律 fail-open，把这类函数标成
// 可空，使所有调用点保留为 null-deref 候选（6 条明确误报 + 4 条疑似）。
func TestNatNullDeref_PoolSectArrayBaseArithmetic(t *testing.T) {
	src := `#include <stdlib.h>

#define POOL_MAX_SECT 64

typedef struct { unsigned int node_id; unsigned short flag; } pool_sect_t;
typedef struct { pool_sect_t sects[POOL_MAX_SECT]; unsigned int sect_cnt; } pool_var_t;

pool_var_t g_pool_var;

static pool_sect_t *POOL_SECT(unsigned int node_id)
{
    return g_pool_var.sects + node_id;
}

static pool_sect_t *find_opt(unsigned int node_id)
{
    if (node_id >= g_pool_var.sect_cnt) { return NULL; }
    return POOL_SECT(node_id);
}

void pool_update_flag(unsigned int node_id, unsigned short flag) {
    pool_sect_t *sect = POOL_SECT(node_id);
    sect->flag = flag;
}

void pool_update_flag_extern(unsigned int node_id, unsigned short flag) {
    pool_sect_t *sect = (pool_sect_t *)(g_pool_var.sects + node_id);
    sect->flag = flag;
}

void real_null_bug(unsigned int node_id) {
    pool_sect_t *sect = find_opt(node_id);
    sect->flag = 1;
}
`
	got := planType(t, src, "null-deref")
	for _, fn := range []string{"pool_update_flag", "pool_update_flag_extern"} {
		if c, ok := got[fn]; ok {
			t.Errorf("%s: array-base pointer arithmetic never returns NULL, should NOT be flagged, got var=%s level=%s line=%d", fn, c.Target.Variable, c.SuspicionLevel, c.Target.Line)
		}
	}
	if _, ok := got["real_null_bug"]; !ok {
		t.Errorf("real_null_bug must still be flagged (find_opt returns literal NULL) (control)")
	}
}
