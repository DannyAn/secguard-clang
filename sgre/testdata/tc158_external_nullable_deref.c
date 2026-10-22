/*
 * TC158 - Null-Deref / Memory Leak: external library nullable returns.
 * xmlDocGetRootElement returns the tree's root node or NULL for an empty
 * document; cJSON_GetObjectItem returns the found item or NULL. The null
 * sources must be seeded through the ExternalAPIs nullable model so an
 * unguarded dereference surfaces (docs §5.1D/§5.2A/§9.2).
 */

#include <stdlib.h>

typedef struct _xmlDoc xmlDoc;
typedef struct _xmlNode xmlNode;
typedef struct cJSON cJSON;

extern xmlDoc *xmlReadMemory(const char *buf, int size, const char *url,
                             const char *enc, int opts);
extern xmlNode *xmlDocGetRootElement(xmlDoc *doc);
extern void xmlFreeDoc(xmlDoc *doc);
extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key);
extern void cJSON_Delete(cJSON *item);

int tc158_external_nullable_deref(const char *buf, int size,
                                  const char *value, const char *key) {
    xmlDoc *doc = xmlReadMemory(buf, size, NULL, NULL, 0);
    if (doc == NULL) return -1;
    xmlNode *root = xmlDocGetRootElement(doc);
    const char *name = root->name;
    xmlFreeDoc(doc);

    cJSON *obj = cJSON_Parse(value);
    if (obj == NULL) return -1;
    cJSON *item = cJSON_GetObjectItem(obj, key);
    int v = item->valueint;
    cJSON_Delete(obj);
    return v + (name != NULL ? 1 : 0);
}