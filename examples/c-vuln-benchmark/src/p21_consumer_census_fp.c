/*
 * Phase 19 — unchecked-return 消费点普查（consumer census）回归防线。
 *
 * 语义（P19 起）：分配结果的"未检查"判定不再只看函数内是否比较过。局部
 * 变量的全部后续消费点均为 NULL 安全时（paramNullSafe 消费调用 + free +
 * sizeof + rebind），分配失败无可观察后果，事件在检测器层抑制（AND 语义：
 * 任一不安全消费保留事件）。字段赋值由下游共享校验函数判空的
 * （fieldNullChecks）同样抑制。入口守卫经 cast 别名
 * （`filter_t *ft = (filter_t *)f; if (ft == NULL) return -1;`）与体内正
 * 守卫全包裹（`if (f != NULL) { ((filter_t *)f)->count = 1; }`）均计入
 * paramNullSafe 摘要。消费通道分档：结果被检查 → callee 必须 NULL→失败
 * 暴露（nullReject）；结果被丢弃或 callee 为 void → callee 只需不解引用
 * NULL（paramNullSafe）。
 * 用例：
 *   UR-01 expect=no_finding  报告模式 A2：int 消费 + 结果丢弃 + 入口/正守卫
 *   UR-02 expect=no_finding  报告模式 4.1：void/int 混合消费全 NULL 防御
 *   UR-03 expect=no_finding  报告模式 4.2：字段逃逸 + 下游共享校验
 *   UR-04 expect=finding     真阳性控制组：分配结果直接解引用
 *   UR-05 expect=finding     census AND 负控：一安全消费 + 一直接解引用
 *   UR-06 expect=finding     值逃逸负控：无守卫转存全局
 *   UR-07 expect=no_finding  void 消费 + 体内正守卫全包裹解引用
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int count;
    int max_num;
    int items[0];
} filter_t;

typedef struct {
    char *user_filter;
    char *dst_name;
} para_t;

typedef struct {
    int len;
    char data[0];
} blob_t;

/* "_new" 名字启发式分配器；OOM 返回 NULL 哨兵。 */
void *ur_filter_new(int max_num)
{
    filter_t *f = (filter_t *)malloc(sizeof(filter_t) + sizeof(int) * (size_t)max_num);
    if (f == NULL) {
        return NULL;
    }
    f->count = 0;
    f->max_num = max_num;
    return f;
}

/* 消费点 1：经 cast 别名的入口守卫（`ft == NULL` 早退失败）。 */
int ur_filter_add(void *f, int item)
{
    filter_t *ft = (filter_t *)f;
    if (ft == NULL || ft->count >= ft->max_num) {
        return -1;
    }
    ft->items[ft->count++] = item;
    return 0;
}

/* 消费点 2：void + 入口守卫。 */
void ur_filter_free(void *f)
{
    if (f == NULL) {
        return;
    }
    free(f);
}

/* 消费点 3：正守卫 —— NULL 走无过滤分支。 */
int ur_filter_traverse(void *f)
{
    if (f != NULL) {
        return ur_filter_add(f, 1);
    }
    return 0;
}

/* 无守卫直接解引用：非 NULL 安全消费。 */
int ur_filter_touch_unsafe(void *f, int item)
{
    filter_t *ft = (filter_t *)f;
    return ft->items[ft->count] + item;
}

/* "strdup" 名字启发式分配器；失败返回 NULL。 */
char *ur_import_strdup(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d == NULL) {
        return NULL;
    }
    memcpy(d, s, n);
    return d;
}

/* 下游共享校验：字段 NULL → 失败返回。 */
int ur_para_is_valid(const para_t *p)
{
    if (p->user_filter == NULL || p->dst_name == NULL) {
        return -1;
    }
    return 0;
}

void ur_para_free(para_t *p)
{
    free(p->user_filter);
    free(p->dst_name);
}

blob_t *ur_blob_dup(const char *s)
{
    size_t n = strlen(s) + 1;
    blob_t *b = (blob_t *)malloc(sizeof(blob_t) + n);
    if (b == NULL) {
        return NULL;
    }
    b->len = (int)n;
    memcpy(b->data, s, n);
    return b;
}

/* UR-01 报告模式 A2：消费点全部 int 返回且结果丢弃（无 void 消费点），
 * 消费者入口守卫 / 正守卫，NULL 无处可崩 —— 不报。 */
int ur01_discard_int_consumers(int key)
{
    void *f = ur_filter_new(2);
    (void)ur_filter_add(f, key);
    ur_filter_traverse(f);
    return 0;
}

/* UR-02 报告模式 4.1：void/int 混合消费，全部 NULL 防御 —— 不报。 */
int ur02_mixed_consumers(int key)
{
    void *f = ur_filter_new(2);
    (void)ur_filter_add(f, key);
    (void)ur_filter_traverse(f);
    ur_filter_free(f);
    return 0;
}

/* UR-03 报告模式 4.2：分配落入结构体字段，下游共享校验函数判空并失败
 * 返回 —— 字段 NULL 已被下游处理，不报。 */
int ur03_field_escape_validated(const char *flt, const char *name)
{
    para_t para;
    memset(&para, 0, sizeof(para));
    para.user_filter = ur_import_strdup(flt);
    para.dst_name = ur_import_strdup(name);
    if (ur_para_is_valid(&para) != 0) {
        ur_para_free(&para);
        return -1;
    }
    ur_para_free(&para);
    return 0;
}

/* UR-04 真阳性控制组：分配结果直接解引用，OOM 即崩 —— 必须报。 */
int ur04_true_positive(const char *s)
{
    blob_t *b = ur_blob_dup(s);
    return b->len + b->data[0];
}

/* UR-05 census AND 负控：一个 NULL 安全消费 + 一次直接解引用 —— 解引用
 * 取消豁免资格，必须报。 */
int ur05_one_unsafe_consumer(int key)
{
    void *f = ur_filter_new(2);
    (void)ur_filter_add(f, key);
    ((filter_t *)f)->count = key;
    return 0;
}

/* UR-06 值逃逸负控：消费者无守卫无解引用，转存全局 —— 值逃逸出函数，
 * 必须报。 */
static void *ur_g_stashed;

void ur_stash_ptr(void *f)
{
    ur_g_stashed = f;
}

int ur06_value_escape(int key)
{
    void *f = ur_filter_new(2);
    ur_stash_ptr(f);
    return 0;
}

/* UR-07 void 消费 + 体内正守卫全包裹解引用 —— paramNullSafe，不报。 */
void ur07_guarded_consumer(void *f)
{
    if (f != NULL) {
        ((filter_t *)f)->count = 1;
    }
}

int ur07_void_guarded_body(int key)
{
    void *f = ur_filter_new(2);
    ur07_guarded_consumer(f);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        return 0;
    }
    int total = ur01_discard_int_consumers(atoi(argv[1]));
    total += ur02_mixed_consumers(atoi(argv[1]));
    total += ur03_field_escape_validated(argv[1], "dst");
    total += ur04_true_positive(argv[1]);
    total += ur05_one_unsafe_consumer(atoi(argv[1]));
    total += ur06_value_escape(atoi(argv[1]));
    total += ur07_void_guarded_body(atoi(argv[1]));
    return total;
}