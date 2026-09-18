#include <stdlib.h>

typedef struct {
    char *content[4];
    unsigned content_len[4];
    unsigned collected[4];
} health_t;

typedef struct {
    health_t local;
    health_t peer;
} health_ctx_t;

health_ctx_t g_health_ctx;

void health_free_content(health_t *health, unsigned type)
{
    health->content_len[type] = 0;
    health->collected[type] = 0;
    if (health->content[type]) {
        char *content = health->content[type];
        health->content[type] = NULL;
        free(content);
    }
}

void health_free_result(unsigned i) { (void)i; }

void health_clear(void)
{
    for (unsigned i = 0; i < 4; i++) {
        health_free_content(&g_health_ctx.local, i);
        health_free_content(&g_health_ctx.peer, i);
        health_free_result(i);
    }
}
