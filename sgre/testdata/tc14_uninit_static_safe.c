/*
 * TC14 - Uninit: Static Safe/Zero-Initialized (REQ-TC-014)
 * Safe pattern: static variables are zero-initialized by the C standard.
 * Expected: NO finding (REQ-TDD-005)
 */

int tc14_uninit_static_safe(void) {
    static int x;
    return x;
}