#define NULL ((void *)0)

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

void *g_buf;

/* T* 输出参数：callee 解引用参数，caller 传 &栈变量（非空） */
void get_one(uint16_t *out)
{
    *out = 1;
}

/* T** 输出参数：指针的指针，callee 解引用一层 */
void get_two(uint16_t **out)
{
    *out = (uint16_t *)g_buf;
}

/* 真实 null-deref 对照：参数被解引用且无守卫，caller 传 NULL */
void deref_param(uint16_t *p)
{
    *p = 0;
}

void caller(uint16_t vrf_id)
{
    uint16_t vsys_id;
    get_one(&vsys_id);

    uint16_t *p;
    get_two(&p);

    uint16_t *q = NULL;
    deref_param(q); /* 真实：q 为 NULL 传给解引用函数 */

    (void)vsys_id;
    (void)p;
    (void)q;
}
