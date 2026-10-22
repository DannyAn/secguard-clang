/*
 * TC147 - Memory Leak: guarded owning add whose failure branch leaks.
 * `if (!cJSON_AddItemToObject(o, "k", item)) return;` — ownership transfers
 * only on success; the failure branch returns with the item still owned by
 * the caller and never deleted. A conditional (non-definite) leak candidate
 * must be reported (docs §9.1: the failure path must not be treated as
 * unconditionally transferred).
 */

#include <stdlib.h>

typedef struct cJSON cJSON;

extern cJSON *cJSON_CreateObject(void);
extern int cJSON_AddItemToObject(cJSON *obj, const char *key, cJSON *item);

int tc147_cjson_add_guard_leak(void) {
    cJSON *o = cJSON_CreateObject();
    if (o == NULL) return -1;
    cJSON *item = cJSON_CreateString("v");
    if (item == NULL) return -1;
    if (!cJSON_AddItemToObject(o, "k", item)) {
        return -1;
    }
    return 0;
}