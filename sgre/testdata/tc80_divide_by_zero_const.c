#include <stdlib.h>

#define BKT_NUM 4096
#define WORKERS 8
#define FLAG (1u << 3)
#define ZERO_VAL 0

enum { HASH_SIZE = 2048, MIN_COUNT = 1 };

const int CACHE_WAYS = 16;

int macro_div_safe(int x) {
    return x / BKT_NUM;      /* safe: macro constant 4096 */
}

int macro_mod_safe(int x) {
    return x % WORKERS;      /* safe: macro constant 8 */
}

int enum_div_safe(int x) {
    return x / HASH_SIZE;    /* safe: enumerator 2048 */
}

int const_div_safe(int x) {
    return x / CACHE_WAYS;   /* safe: const int 16 */
}

int macro_shift_expr(int x) {
    return x / FLAG;         /* DIVIDE_BY_ZERO: (1u << 3) not resolved, kept conservatively */
}

int macro_zero_div(int x) {
    return x / ZERO_VAL;     /* DIVIDE_BY_ZERO: genuinely zero divisor, must stay flagged */
}

int var_div_unsafe(int x, int y) {
    return x / y;            /* DIVIDE_BY_ZERO: y may be 0 */
}