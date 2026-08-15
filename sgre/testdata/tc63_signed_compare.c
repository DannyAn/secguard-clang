#include <stddef.h>
#include <stdint.h>

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
