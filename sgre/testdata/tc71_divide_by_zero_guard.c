#include <stdlib.h>

int clamp_guard_safe(int x, int n) {
    if (n == 0) n = 1; /* n non-zero on fall-through */
    return x / n;      /* safe: no DIVIDE_BY_ZERO event */
}

int negate_guard_safe(int x, int n) {
    if (!n) n = 1;     /* n non-zero on fall-through */
    return x / n;      /* safe: no DIVIDE_BY_ZERO event */
}

int compound_guard_safe(int x, int n) {
    if (n == 0) {
        n = 1;
    }
    return x / n;      /* safe: no DIVIDE_BY_ZERO event */
}

int still_unsafe(int x, int n) {
    return x / n;      /* DIVIDE_BY_ZERO: n may be 0 */
}
