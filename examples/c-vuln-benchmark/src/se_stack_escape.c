// se_stack_escape.c — stack-address-escape (CWE-562) benchmark cases.
#include <pthread.h>

int *g_ptr;
struct ctx { int *cb; };
struct point { int x; };

static int *helper(int *p) { return p; }

int *se01_return_addr(void) {
    int local = 0;
    return &local;
}

int *se02_return_array(void) {
    int arr[4];
    return arr;
}

int *se03_return_field_addr(void) {
    struct point p;
    return &p.x;
}

void se04_store_global(void) {
    int local = 0;
    g_ptr = &local;
}

void *thread_body(void *arg) { return arg; }

void se05_pthread_arg(void) {
    int local = 0;
    pthread_t t;
    pthread_create(&t, 0, thread_body, &local);
}

int *se10_static_local(void) {
    static int s = 0;
    return &s;
}

int *se11_return_global(void) {
    return g_ptr;
}

int *se12_return_string(void) {
    return (int *)"literal";
}

int *se13_helper_arg(void) {
    int local = 0;
    return helper(&local);
}
