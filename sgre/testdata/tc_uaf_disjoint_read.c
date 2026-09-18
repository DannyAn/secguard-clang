#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    unsigned len;
} health_msg_ctx_t;

health_msg_ctx_t g_health_msg_ctx;

/* Mirrors the reported false positive: the first free(g_health_msg_ctx.data)
 * is on a branch that returns immediately, so the later read of
 * g_health_msg_ctx.data (the memcpy_s source) and the second free cannot observe
 * a prior free. */
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
    if (memcpy_s(data, len, g_health_msg_ctx.data, len) != 0) {
        free(data);
        free(g_health_msg_ctx.data);
        g_health_msg_ctx.data = NULL;
        g_health_msg_ctx.len = 0;
        return -1;
    }
    return 0;
}
