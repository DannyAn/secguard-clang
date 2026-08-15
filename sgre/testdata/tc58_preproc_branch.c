/* x is assigned in BOTH preprocessor branches (and the else branch), so it is
 * definitely initialized on every path. The preprocessor branches are inside
 * an if, which the coarse detector flags, and the planner's flow filter drops. */
int preproc_both_nested(int flag) {
    int x;
    if (flag) {
#ifdef USE_A
        x = 1;
#else
        x = 2;
#endif
    } else {
        x = 3;
    }
    return x;
}

/* x is assigned in only ONE preprocessor branch (and not in the else), so it
 * is possibly uninitialized (when flag is false or USE_A is undefined). */
int preproc_one_nested(int flag) {
    int x;
    if (flag) {
#ifdef USE_A
        x = 1;
#endif
    }
    return x;
}

/* x is assigned under #ifdef USE_A (region 1) and used under #ifdef USE_A
 * (region 2, in a nested runtime scope): the assignment covers the use on the
 * same compile-time condition, so it is not uninitialized. */
int preproc_cross_region(int endian, int n) {
    int x;
    int sum = 0;
    if (endian) {
#ifdef USE_A
        x = 1;
#endif
        while (n-- > 0) {
#ifdef USE_A
            sum += x;
#endif
        }
    }
    return sum;
}
