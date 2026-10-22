/*
 * TC143 - Memory Leak: XPath result object released with the WRONG family.
 * xmlXPathEvalExpression allocates an XPath OBJECT whose only legal releaser
 * is xmlXPathFreeObject; handing it to xmlXPathFreeContext (the CONTEXT
 * releaser) must NOT count as a release — the object leaks (docs §9.1).
 */

#include <stdlib.h>

typedef struct _xmlDoc xmlDoc;
typedef struct _xmlXPathContext xmlXPathContext;
typedef struct _xmlXPathObject xmlXPathObject;

extern xmlXPathContext *xmlXPathNewContext(xmlDoc *doc);
extern void xmlXPathFreeContext(xmlXPathContext *ctx);
extern xmlXPathObject *xmlXPathEvalExpression(const char *expr,
                                               xmlXPathContext *ctx);

void tc143_xml_xpath_mismatch(xmlDoc *doc, const char *expr) {
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