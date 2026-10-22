/*
 * TC161 - cJSON Detach (user-provided canonical form): DetachItemFromObject
 * removes the item from the parent and hands its ownership to the caller,
 * which then deletes it; the root is deleted separately. Both ownership
 * chains are correctly paired — no leak, no null-deref.
 */

#include <stdlib.h>

typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;

extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_DetachItemFromObject(cJSON *obj, const char *key);
extern void cJSON_Delete(cJSON *item);

void tc161_cjson_detach_ok(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_DetachItemFromObject(root, "name");
    if (name != NULL) {
        /* 已从 root 脱离，所有权由调用方负责 */
        cJSON_Delete(name);
    }

    cJSON_Delete(root);
}