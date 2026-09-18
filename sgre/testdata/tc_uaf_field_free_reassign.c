#include <stdlib.h>
#include <string.h>

typedef struct {
    char *content[8];
    unsigned content_len[8];
    unsigned collected[8];
} health_t;

/* health_free_content frees a FIELD (health->content[type]) via a local alias,
 * not the health argument itself. Calling it and then reassigning
 * health->content[type] must NOT be a use-after-free. */
static void health_free_content(health_t *health, unsigned type)
{
    health->content_len[type] = 0;
    health->collected[type] = 0;
    if (health->content[type]) {
        char *content = health->content[type];
        health->content[type] = NULL;
        free(content);
    }
}

void health_content_update(health_t *health, const char *detail, unsigned content_type)
{
    char *tmp = (char *)malloc(128);
    if (tmp == NULL) {
        return;
    }
    memcpy(tmp, detail, 128);
    health_free_content(health, content_type);
    health->content[content_type] = tmp;
    health->content_len[content_type] = 128;
    health->collected[content_type] = 1;
}
