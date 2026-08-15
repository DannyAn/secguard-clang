/* A chained assignment initializes every target; the RHS targets are writes,
 * not reads. `code = first = index = 0` must not report first/index as
 * use-before-init. */
int chained_assign_initializes_all(void) {
    int first;
    int index;
    int code;
    code = first = index = 0;
    return first + index + code;
}

/* A genuine uninitialized read must still be reported. */
int genuine_uninit(void) {
    int a;
    return a + 1;
}
