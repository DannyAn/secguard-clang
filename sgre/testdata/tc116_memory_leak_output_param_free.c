/*
 * TC116 - Memory Leak: Free through dereferenced output parameter
 * The allocation is stored through *root and freed through *root on
 * all paths. argIdentifier must unwrap pointer_dereference_expression
 * so cJSON_Delete(*root) is recognized as a release of "root", and
 * the allocation is not reported as a leak.
 */

#include <stdlib.h>

typedef struct cJSON { int type; } cJSON;

cJSON *cJSON_CreateObject(void);
void cJSON_Delete(cJSON *obj);

int tc116_output_param_free(cJSON **root) {
    *root = cJSON_CreateObject();
    if (!*root) return -1;
    (*root)->type = 0;
    cJSON_Delete(*root);
    *root = NULL;
    return 0;
}