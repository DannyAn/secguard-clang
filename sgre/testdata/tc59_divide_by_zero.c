#include <stdlib.h>

int safe_constant_div(int x) {
    return x / 100; /* safe: non-zero constant divisor */
}

int safe_sizeof_div(int x) {
    return x / sizeof(int); /* safe: compile-time constant */
}

int unsafe_var_div(int x, int y) {
    return x / y; /* DIVIDE_BY_ZERO: y may be 0 */
}

int unsafe_expr_mod(int a, int b, int c) {
    return a % (b - c); /* DIVIDE_BY_ZERO: (b - c) may be 0 */
}

float safe_float_division(void) {
    return 1.0f / 0.0f; /* no event: float division by zero is IEEE-defined Inf/NaN, not CWE-369 */
}
