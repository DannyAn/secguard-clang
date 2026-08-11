#ifndef SECGUARD_TEST_HELPERS_H
#define SECGUARD_TEST_HELPERS_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNUSED(x) ((void)(x))

static void *sg_safe_malloc(size_t n) {
    void *p = malloc(n);
    if (!p) {
        return NULL;
    }
    memset(p, 0, n);
    return p;
}

#endif