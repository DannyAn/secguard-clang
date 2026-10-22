/*
 * TC142 - Memory Leak: both XPath pairs released correctly.
 * xmlXPathNewContext pairs with xmlXPathFreeContext, and
 * xmlXPathEvalExpression pairs with xmlXPathFreeObject. Both objects exist
 * in the same function with their own (different) releasers — a regression
 * fixture for the family-pairing rule (docs §5.1: context and result object
 * are different types with different releasers).
 */

#include <stdlib.h>

typedef struct _xmlDoc xmlDoc;
typedef struct _xmlXPathContext xmlXPathContext;
typedef struct _xmlXPathObject xmlXPathObject;

extern xmlXPathContext *xmlXPathNewContext(xmlDoc *doc);
extern void xmlXPathFreeContext(xmlXPathContext *ctx);
extern xmlXPathObject *xmlXPathEvalExpression(const char *expr,
                                               xmlXPathContext *ctx);
extern void xmlXPathFreeObject(xmlXPathObject *obj);

void tc142_xml_xpath_pair(xmlDoc *doc, const char *expr) {
    xmlXPathContext *ctx = xmlXPathNewContext(doc);
    if (ctx == NULL) return;
    xmlXPathObject *obj = xmlXPathEvalExpression(expr, ctx);
    if (obj == NULL) {
        xmlXPathFreeContext(ctx);
        return;
    }
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctx);
}