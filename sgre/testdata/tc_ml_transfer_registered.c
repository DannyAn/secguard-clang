/*
 * Memory-leak: config-driven ownership transfer regression lock (issue #289 T1).
 * queue_write_w is declared but has no in-tree body, and its name matches none
 * of the IsEscapeFunction naming tokens — the ONLY way it is recognized as an
 * ownership transfer is RegisterOwnershipTransfer (secguard.toml
 * [ownership_transfer_calls]). This locks the existing config path alongside
 * the new callee-body inference.
 */

#include <stdlib.h>

struct msg_w {
    void *payload;
};

extern int queue_write_w(struct msg_w *m, void *p);

void tc_ml_transfer_registered(struct msg_w *m)
{
    void *ptr = malloc(64);
    if (ptr == NULL) {
        return;
    }
    queue_write_w(m, ptr);
}
