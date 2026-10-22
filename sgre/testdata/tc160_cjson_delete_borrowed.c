/*
 * TC160 - cJSON misuse (user-provided canonical form): an item borrowed from
 * the parent tree is deleted on its own. cJSON_GetObjectItem returns a
 * borrowed pointer owned by the root; cJSON_Delete(name) releases an object
 * the caller does not own — use-after-free / double-free / heap corruption
 * risk when cJSON_Delete(root) later walks the child list. The free-on-borrow
 * channel must surface a candidate for this.
 */

#include <stdlib.h>

typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;

extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key);
extern void cJSON_Delete(cJSON *item);

void tc160_delete_borrowed_item(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");

    /* 错误：name 是 root 内部的借用指针 */
    cJSON_Delete(name);

    /* root 的子项链表仍可能指向已释放的 name */
    cJSON_Delete(root);
}