#include <stdint.h>
#include <stdlib.h>

struct Inner {
    uint64_t a;
    uint64_t b;
};

struct Outer {
    uint64_t id;
    struct Inner inner;
};

uint64_t read_inner(void)
{
    struct Outer *outer = (struct Outer *)malloc(16);
    if (outer == NULL) {
        return 0;
    }

    outer->inner.a = 1;
    return outer->inner.a;
}
