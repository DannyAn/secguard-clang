/* tc117_guard_parser_drift.c — NE-02/NE-11 regression fixture.
 * ne02: `p != q` compares two non-null operands and is NOT a null guard;
 * ne11: `unlikely(p != NULL)` is a branch-hint-wrapped null guard. */
typedef struct { int x; } T;

void ne02_not_null_cmp(T *w, T *q) {
    if (w != q) {
        w->x = 1;
    }
}

void ne11_unlikely_guard(T *p) {
    if (unlikely(p != NULL)) {
        p->x = 1;
    }
}