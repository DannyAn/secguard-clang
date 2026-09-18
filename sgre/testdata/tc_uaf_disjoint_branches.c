#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    unsigned len;
} health_msg_ctx_t;

health_msg_ctx_t g_health_msg_ctx;

/* The two free(g_health_msg_ctx.data) calls are on MUTUALLY EXCLUSIVE branches:
 * the first branch returns -1 immediately, so the second branch cannot observe
 * a prior free. This must NOT be a double-free / use-after-free. */
int health_query(void)
{
    if (g_health_msg_ctx.len == 0 || g_health_msg_ctx.data == NULL) {
        return -1;
    }
    unsigned len = g_health_msg_ctx.len;
    char *data = (char *)malloc(len);
    if (data == NULL) {
        free(g_health_msg_ctx.data);
        g_health_msg_ctx.data = NULL;
        g_health_msg_ctx.len = 0;
        return -1;
    }
    if (len > 100) {
        free(data);
        free(g_health_msg_ctx.data);
        g_health_msg_ctx.data = NULL;
        g_health_msg_ctx.len = 0;
        return -1;
    }
    return 0;
}
