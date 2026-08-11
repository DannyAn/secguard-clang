/* sample.c - 5 functions: 2 static, 3 non-static, various return types */
#include <stdlib.h>

static int helper_add(int a, int b) {
    return a + b;
}

static void helper_noop(void) {
    return;
}

int compute(int x) {
    return helper_add(x, 1);
}

char *get_name(void) {
    return "test";
}

void *alloc_thing(size_t n) {
    return malloc(n);
}