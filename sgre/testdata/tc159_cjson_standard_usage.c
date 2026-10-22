/*
 * TC159 - cJSON standard usage (user-provided canonical form): create,
 * attach, print, and one unified release. Three ownership rules exercised:
 * Create*/Parse own until transferred, AddItemToObject hands the item to the
 * parent on success (failure branch deletes it), PrintUnformatted's string
 * is a standalone buffer released by cJSON_free. No leak, no null-deref.
 */

#include <stdio.h>
#include <stdlib.h>

typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;

extern cJSON *cJSON_CreateObject(void);
extern cJSON *cJSON_CreateString(const char *s);
extern int cJSON_AddItemToObject(cJSON *obj, const char *key, cJSON *item);
extern char *cJSON_PrintUnformatted(const cJSON *item);
extern void cJSON_Delete(cJSON *item);
extern void cJSON_free(void *p);

int main(void)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return 1;
    }

    cJSON *name = cJSON_CreateString("Alice");
    if (name == NULL) {
        cJSON_Delete(root);
        return 1;
    }

    if (!cJSON_AddItemToObject(root, "name", name)) {
        /* 添加失败：调用方仍须负责处理 name */
        cJSON_Delete(name);
        cJSON_Delete(root);
        return 1;
    }

    /* root 拥有 name，不能再单独删除 name */
    char *json = cJSON_PrintUnformatted(root);
    if (json == NULL) {
        cJSON_Delete(root);
        return 1;
    }

    puts(json);

    cJSON_free(json);  /* 释放 cJSON_Print 分配的输出缓冲区 */
    cJSON_Delete(root); /* 递归释放 root 及其拥有的子项 */

    return 0;
}