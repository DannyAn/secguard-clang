/*
 * TC15 - Uninit: Conditional Init / Path-Sensitive (REQ-TC-015)
 * Vulnerability: a variable is initialized only on some paths and used
 *                on a path where it was not initialized.
 * Expected: finding produced (path-sensitive uninit use)
 */

int tc15_uninit_conditional(int flag) {
    int x;
    if (flag) {
        x = 42;
    }
    return x;
}