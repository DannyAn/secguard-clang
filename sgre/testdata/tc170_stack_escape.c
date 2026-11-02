#include <pthread.h>

int *g_ptr;
struct ctx { int *cb; };
struct point { int x; int y; };

static int *helper(int *p) { return p; }

int *m1a_return_addr(void) {
    int local = 0;
    return &local;
}

int *m1b_return_array(void) {
    int arr[4];
    return arr;
}

int *m1c_return_elem_addr(void) {
    int arr[4];
    return &arr[2];
}

int *m1d_return_field_addr(void) {
    struct point p;
    return &p.x;
}

void m2_store(struct ctx *obj) {
    int local = 0;
    g_ptr = &local;
    obj->cb = &local;
}

void *thread_body(void *arg) { return arg; }

void m3_async_arg(void) {
    int local = 0;
    pthread_t t;
    pthread_create(&t, NULL, thread_body, &local);
}

int *fp_static_local(void) {
    static int s = 0;
    return &s;
}

int *fp_global(void) {
    return g_ptr;
}

int *fp_sync_helper(void) {
    int local = 0;
    return helper(&local);
}

int *fp_string(void) {
    return (int *)"literal";
}

/* &h[i] on a local POINTER equals h + i (points into the pointee, not the
   frame); it is not an escape of a stack address. */
const void *fp_pointer_subscript(const void *haystack, unsigned len) {
    if (!haystack || !len) return 0;
    const unsigned char *h = (const unsigned char *)haystack;
    for (unsigned i = 0; i < len; i++) {
        if (h[i] == 'x') return &h[i];
    }
    return 0;
}

int main(void) {
    struct ctx c;
    m2_store(&c);
    m3_async_arg();
    return m1a_return_addr() != 0;
}
