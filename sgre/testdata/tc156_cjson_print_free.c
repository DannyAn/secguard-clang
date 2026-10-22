/*
 * TC156 - Memory Leak: cJSON printed string released with free() (legal).
 * cJSON_Print's string is a plain malloc'd buffer; cJSON_free IS free by
 * default (cJSON 1.7), so the generic free() is a VALID release and the
 * root object is deleted with cJSON_Delete. No leak (docs §5.2B).
 */

#include <stdlib.h>

typedef struct cJSON cJSON;

extern cJSON *cJSON_Parse(const char *value);
extern char *cJSON_Print(const cJSON *item);
extern void cJSON_Delete(cJSON *item);

void tc156_cjson_print_free(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) return;
    char *s = cJSON_Print(root);
    if (s != NULL) {
        free(s);
    }
    cJSON_Delete(root);
}