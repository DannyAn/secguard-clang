/*
 * TC162 - cJSON Detach misuse: the detached item is caller-owned but never
 * deleted — a definite leak (the object left the parent tree, so the root's
 * cJSON_Delete does NOT cover it).
 */

#include <stdlib.h>

typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;

extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_DetachItemFromObject(cJSON *obj, const char *key);
extern void cJSON_Delete(cJSON *item);

void tc162_cjson_detach_leak(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_DetachItemFromObject(root, "name");
    if (name == NULL) {
        cJSON_Delete(root);
        return;
    }

    cJSON_Delete(root);
}