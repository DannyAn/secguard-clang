/*
 * TC154 - Memory Leak: cJSON parse root deleted (correct pairing) and an
 * unchecked owning add of a created child (transfer on the unchecked form).
 * Neither item nor root is a leak: the child rides with the root's lifetime
 * once attached, and the root is deleted (docs §5.2A/§5.2C).
 */

#include <stdlib.h>

typedef struct cJSON cJSON;

extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_CreateString(const char *s);
extern int cJSON_AddItemToObject(cJSON *obj, const char *key, cJSON *item);
extern void cJSON_Delete(cJSON *item);

void tc154_cjson_parse_delete(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) return;
    cJSON *item = cJSON_CreateString("v");
    if (item == NULL) {
        cJSON_Delete(root);
        return;
    }
    cJSON_AddItemToObject(root, "k", item);
    cJSON_Delete(root);
}