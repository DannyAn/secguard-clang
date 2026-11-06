#include <stdint.h>
#include <stdlib.h>

struct Outer {
    struct Inner {
        uint32_t a;
        uint32_t b;
    } n;
    uint32_t c;
};

int read_outer(void)
{
    struct Outer *p = (struct Outer *)malloc(12);
    if (p == NULL) {
        return -1;
    }

    p->c = 1;

    free(p);
    return 0;
}
