/* The for-initializer runs before the condition, so `i` in `for (i=0; i<n; i++)`
 * is initialized before the condition reads it — must not be use-before-init. */
int for_init_initializes_i(int n) {
    int i;
    int sum = 0;
    for (i=0; i<n; i++) {
        sum += i;
    }
    return sum;
}

/* A loop variable genuinely used before initialization must still be flagged. */
int genuine_while_uninit(int n) {
    int j;
    while (j < n) {
        j++;
    }
    return j;
}
