/*
 * TC163 - boundary: after a checked owning add SUCCEEDS, the item is owned
 * by the parent; deleting it as well is a cross-object double free (out of
 * scope for the leak detector) — the leak side must stay silent either way
 * (no false leak either for the transferred item or for the root).
 */

#include <stdlib.h>

typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;

extern cJSON *cJSON_CreateObject(void);
extern cJSON *cJSON_CreateString(const char *s);
extern int cJSON_AddItemToObject(cJSON *obj, const char *key, cJSON *item);
extern void cJSON_Delete(cJSON *item);

void tc163_cjson_add_then_delete_item(void) {
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return;
    cJSON *name = cJSON_CreateString("v");
    if (name == NULL) {
        cJSON_Delete(root);
        return;
    }
    if (!cJSON_AddItemToObject(root, "k", name)) {
        cJSON_Delete(name);
        cJSON_Delete(root);
        return;
    }
    cJSON_Delete(name);
    cJSON_Delete(root);
}