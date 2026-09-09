#define ZERO 0

int lit(int x) {
    return x / 0;      /* literal zero: definite divide-by-zero */
}

int sym(int x) {
    return x / ZERO;   /* zero-valued symbol: definite divide-by-zero */
}

int assigned(int x) {
    int d = 0;
    return x / d;      /* d=0 via interval: definite divide-by-zero */
}

int var_div(int x, int d) {
    return x / d;      /* unknown divisor: suspected */
}
