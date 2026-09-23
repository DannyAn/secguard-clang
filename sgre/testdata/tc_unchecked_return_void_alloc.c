#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int len;
} Mbuf;

void test_case_alloc(Mbuf *mbuf, int ecode)
{
    mbuf->len = ecode;
}

void caller_void_alloc(void)
{
    Mbuf *mbuf = (Mbuf *)malloc(sizeof(Mbuf));
    if (mbuf == NULL) {
        return;
    }
    test_case_alloc(mbuf, 1);
    free(mbuf);
}

int check_alloc_status(int id)
{
    return id == 0;
}

void caller_scalar_alloc_name(void)
{
    int ret = check_alloc_status(42);
    (void)ret;
}

void *my_alloc(size_t n)
{
    return malloc(n);
}

void *passthrough_wrapper(size_t n)
{
    return my_alloc(n);
}

void caller_passthrough_wrapper(void)
{
    void *p = passthrough_wrapper(64);
    (void)p;
}

void is_allocated(int id)
{
    (void)id;
}

void void_passthrough(void)
{
    return is_allocated(1);
}

void caller_void_passthrough(void)
{
    void_passthrough();
}

int unchecked_malloc_still_works(void)
{
    int *p = (int *)malloc(sizeof(int) * 10);
    return p[0];
}
