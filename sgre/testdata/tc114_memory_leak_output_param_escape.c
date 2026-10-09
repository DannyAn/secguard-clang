/*
 * TC114 - Memory Leak: Output parameter escape via *param = malloc()
 * The allocation is stored through *root (a dereferenced output parameter)
 * and NOT freed locally — ownership is transferred to the caller, which
 * frees it after use. findEscapeLines must recognize *root = malloc() as
 * an escape (non-local base, pointer_dereference_expression lhs) so the
 * allocation is not reported as a leak.
 */
 
#include <stdlib.h>
 
typedef struct cJSON { int type; } cJSON;
 
int tc114_output_param_escape(cJSON **root) {
    *root = malloc(sizeof(cJSON));
    if (!*root) return -1;
    (*root)->type = 0;
    return 0;
}