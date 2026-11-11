#include <stdlib.h>
#include <string.h>

// Issue #261 item 8: the only non-null-guard early return is the failure branch
// of a NON-FAILABLE safe copy — memcpy_s(dst, sizeof(dst), src, sizeof(dst))
// copies equal-sized objects and cannot trip the `_s` constraint handler, so
// that branch is unreachable and the buffer must NOT be reported as a leak.
void tc192_memcpy_s_nonfailable(char *dst, char *src, int n) {
    char *buf = (char *)malloc(256);
    if (buf == NULL) return;
    for (int i = 0; i < n; i++) {
        if (memcpy_s(dst, sizeof(dst), src, sizeof(dst)) != 0) {
            return;
        }
    }
    free(buf);
}
