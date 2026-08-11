/*
 * TC11 - Uninit: Stack Variable Use Without Init (REQ-TC-011)
 * Vulnerability: a stack variable is read before being written.
 * Expected: finding produced (uninitialized stack read)
 */

int tc11_uninit_stack(void) {
    int x;
    return x;
}