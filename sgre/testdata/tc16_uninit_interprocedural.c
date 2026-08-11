/*
 * TC16 - Uninit: Interprocedural Init via Pointer (REQ-TC-016)
 * Vulnerability: a variable is expected to be initialized via a pointer
 *                passed to another function, but on a failure path the
 *                callee does not write through the pointer, leaving the
 *                variable uninitialized.
 * Expected: finding produced (interprocedural uninit)
 */

static int init_via_ptr(int *out, int fail) {
    if (fail) {
        return -1;
    }
    *out = 99;
    return 0;
}

int tc16_uninit_interprocedural(int fail) {
    int x;
    int rc = init_via_ptr(&x, fail);
    if (rc != 0) {
        return x;
    }
    return x;
}