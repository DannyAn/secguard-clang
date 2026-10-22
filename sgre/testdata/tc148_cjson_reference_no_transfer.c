/*
 * TC148 - Memory Leak: reference add does NOT transfer ownership.
 * cJSON_AddItemReferenceToObject stores a REFERENCE; the original item's
 * ownership stays with the caller, which must still delete it. Under the old
 * `_add` escape heuristic this was misread as a transfer (leak missed);
 * the ExternalAPIs Borrow model must keep the leak reported (docs §5.2C).
 */

#include <stdlib.h>

typedef struct cJSON cJSON;

extern cJSON *cJSON_CreateObject(void);
extern cJSON *cJSON_CreateString(const char *s);
extern int cJSON_AddItemReferenceToObject(cJSON *obj, const char *key,
                                          cJSON *item);

void tc148_cjson_reference_no_transfer(void) {
    cJSON *o = cJSON_CreateObject();
    if (o == NULL) return;
    cJSON *item = cJSON_CreateString("v");
    if (item == NULL) return;
    cJSON_AddItemReferenceToObject(o, "ref", item);
}