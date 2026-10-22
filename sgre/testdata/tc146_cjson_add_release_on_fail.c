/*
 * TC146 - Memory Leak: owning add with a failure-branch release.
 * `if (!cJSON_AddItemToObject(o, "k", item)) { cJSON_Delete(item); return; }`
 * — success transfers the item to the parent (escape) and failure deletes
 * it (free). Both leak-avoiding channels exist, so no leak is reported on
 * either path (docs §5.2C).
 */

#include <stdlib.h>

typedef struct cJSON cJSON;

extern cJSON *cJSON_CreateObject(void);
extern int cJSON_AddItemToObject(cJSON *obj, const char *key, cJSON *item);
extern void cJSON_Delete(cJSON *item);

int tc146_cjson_add_release_on_fail(void) {
    cJSON *o = cJSON_CreateObject();
    if (o == NULL) return -1;
    cJSON *item = cJSON_CreateString("v");
    if (item == NULL) {
        cJSON_Delete(o);
        return -1;
    }
    if (!cJSON_AddItemToObject(o, "k", item)) {
        cJSON_Delete(item);
        cJSON_Delete(o);
        return -1;
    }
    cJSON_Delete(o);
    return 0;
}