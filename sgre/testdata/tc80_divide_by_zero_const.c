#include <stdlib.h>

#define BKT_NUM 4096
#define WORKERS 8
#define FLAG (1u << 3)
#define SECONDS_PER_DAY (24 * 60 * 60)
#define SEC_PER_MIN 60
#define MIN_PER_HOUR 60
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
    return x / FLAG;         /* safe: (1u << 3) folds to non-zero 8 */
}

int macro_compound_div(int x) {
    return x / SECONDS_PER_DAY;  /* safe: (24 * 60 * 60) folds to non-zero */
}

int macro_symbol_product(int x) {
    return x / (MIN_PER_HOUR * SEC_PER_MIN);  /* safe: product of non-zero constants */
}

int macro_zero_div(int x) {
    return x / ZERO_VAL;     /* DIVIDE_BY_ZERO: genuinely zero divisor, must stay flagged */
}

int var_div_unsafe(int x, int y) {
    return x / y;            /* DIVIDE_BY_ZERO: y may be 0 */
}