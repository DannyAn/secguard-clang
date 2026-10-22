/*
 * Phase 26 — third-party external API semantics (docs/secguard-clang支持第三方库函数.md).
 * Each case pairs a library API with its modeled allocation/release/ownership/
 * nullability contract: xml/cJSON specialized pairings, family-mismatch
 * releases, reference-vs-owning adds, asprintf success-branch binding, and
 * nullable-borrow dereferences.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _xmlDoc { struct _xmlNode *children; } xmlDoc;
typedef struct _xmlNode { const char *name; struct _xmlNode *next; } xmlNode;
typedef struct _xmlXPathContext { int node; } xmlXPathContext;
typedef struct _xmlXPathObject { int type; } xmlXPathObject;
typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;

extern xmlDoc *xmlReadMemory(const char *buf, int size, const char *url,
                             const char *enc, int opts);
extern void xmlFreeDoc(xmlDoc *doc);
extern xmlNode *xmlDocGetRootElement(xmlDoc *doc);
extern xmlXPathContext *xmlXPathNewContext(xmlDoc *doc);
extern void xmlXPathFreeContext(xmlXPathContext *ctx);
extern xmlXPathObject *xmlXPathEvalExpression(const char *expr,
                                               xmlXPathContext *ctx);
extern void xmlXPathFreeObject(xmlXPathObject *obj);
extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_CreateString(const char *s);
extern cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key);
extern int cJSON_AddItemToObject(cJSON *obj, const char *key, cJSON *item);
extern int cJSON_AddItemReferenceToObject(cJSON *obj, const char *key,
                                          cJSON *item);
extern void cJSON_Delete(cJSON *item);

/* P26-01 (finding, CWE-401): xmlReadMemory's caller-owned xmlDoc is never
 * released and never transferred — a definite leak. */
void p26_leak_xml_doc(const char *buf, int size) {
    xmlDoc *doc = xmlReadMemory(buf, size, NULL, NULL, 0);
    if (doc == NULL) return;
}

/* P26-02 (no_finding, CWE-401): correct document pairing — xmlFreeDoc on
 * every path after the null guard. */
void p26_xml_pair_ok(const char *buf, int size) {
    xmlDoc *doc = xmlReadMemory(buf, size, NULL, NULL, 0);
    if (doc == NULL) return;
    xmlFreeDoc(doc);
}

/* P26-03 (finding, CWE-401): the XPath result OBJECT is handed to
 * xmlXPathFreeContext — the CONTEXT releaser. The family pairing rejects
 * the release, so the object leaks. */
void p26_xpath_mismatch(xmlDoc *doc, const char *expr) {
    xmlXPathContext *ctx = xmlXPathNewContext(doc);
    if (ctx == NULL) return;
    xmlXPathObject *obj = xmlXPathEvalExpression(expr, ctx);
    if (obj == NULL) {
        xmlXPathFreeContext(ctx);
        return;
    }
    xmlXPathFreeContext((xmlXPathContext *)obj);
    xmlXPathFreeContext(ctx);
}

/* P26-04 (finding, CWE-401): a reference add does NOT transfer ownership —
 * the caller-created item stays owned by the caller and is never deleted
 * (the root itself IS correctly deleted so the case stays focused). */
void p26_cjson_reference_leak(const char *value) {
    cJSON *o = cJSON_Parse(value);
    if (o == NULL) return;
    cJSON *item = cJSON_CreateString("v");
    if (item == NULL) {
        cJSON_Delete(o);
        return;
    }
    cJSON_AddItemReferenceToObject(o, "ref", item);
    cJSON_Delete(o);
}

/* P26-05 (no_finding, CWE-401): correct cJSON pairing on every path. */
void p26_cjson_pair_ok(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) return;
    cJSON_Delete(root);
}

/* P26-06 (no_finding, CWE-401): the asprintf out-param allocation exists
 * only on the success branch — the failure early-return is not leak
 * evidence and the success path frees. */
int p26_asprintf_fail_guard_ok(const char *name) {
    char *p = NULL;
    if (asprintf(&p, "hello %s", name) < 0) {
        return -1;
    }
    printf("%s\n", p);
    free(p);
    return 0;
}

/* P26-07 (finding, CWE-476): the borrowed root from xmlDocGetRootElement
 * (maybe-NULL for an empty document) is dereferenced without a null guard. */
void p26_xml_root_deref(const char *buf, int size) {
    xmlDoc *doc = xmlReadMemory(buf, size, NULL, NULL, 0);
    if (doc == NULL) return;
    const char *name = xmlDocGetRootElement(doc)->name;
    printf("%s\n", name);
    xmlFreeDoc(doc);
}

/* P26-08 (no_finding, CWE-476): the fully guarded cJSON lookup chain —
 * no dereference of an unchecked maybe-NULL result. */
void p26_cjson_lookup_guarded_ok(const char *value) {
    cJSON *obj = cJSON_Parse(value);
    if (obj == NULL) return;
    cJSON *item = cJSON_GetObjectItem(obj, "count");
    if (item != NULL) {
        printf("%d\n", item->valueint);
    }
    cJSON_Delete(obj);
}