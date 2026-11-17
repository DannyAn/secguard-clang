/*
 * Memory-leak: callee-body ownership-transfer inference (issue #289 T1).
 * queue_write stores its second parameter into a non-local object
 * (m->payload = p) so the callee provably takes ownership of that argument,
 * even though the name carries no _put/_push/_queue/... token and it is not
 * registered in [ownership_transfer_calls]. The caller's ptr must therefore
 * be released (escaped), not leaked.
 */

#include <stdlib.h>

struct msg {
    void *payload;
};

extern struct msg *g_queue_tail;

/* callee 把第 2 个参数存进非本地对象：所有权交付证据 */
int queue_write(struct msg *m, void *p)
{
    m->payload = p;
    g_queue_tail = m;
    return 0;
}

void tc_ml_transfer_inferred(struct msg *m)
{
    void *ptr = malloc(64);
    if (ptr == NULL) {
        return;
    }
    if (queue_write(m, ptr) != 0) {
        free(ptr);
        return;
    }
}
