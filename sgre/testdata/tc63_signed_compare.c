#include <stddef.h>
#include <stdint.h>

typedef unsigned int my_uint;

void safe_signed_compare(int x) {
    if (x < 0) {
        return; /* x is signed: valid check */
    }
}

void unsafe_unsigned_compare(size_t len) {
    if (len < 0) { /* SIGNED_COMPARE: len is unsigned, always false */
        return;
    }
}

void unsafe_uint32_compare(uint32_t count) {
    if (count <= -1) { /* SIGNED_COMPARE: always false */
        return;
    }
}

int unsafe_unsigned_loop(size_t n) {
    size_t i;
    for (i = n; i >= 0; i--) { /* SIGNED_COMPARE: never terminates */
        return 1;
    }
    return 0;
}

int unsafe_unsigned_initialized(int n) {
    unsigned int k = n;
    if (k < 0) { /* SIGNED_COMPARE: initialized unsigned var, always false */
        return 1;
    }
    return 0;
}

int unsafe_unsigned_typedef(my_uint m) {
    if (m < 0) { /* SIGNED_COMPARE: my_uint resolves to unsigned int */
        return 1;
    }
    return 0;
}
