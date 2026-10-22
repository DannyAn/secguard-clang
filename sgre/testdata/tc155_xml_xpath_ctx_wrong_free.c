/*
 * TC155 - Memory Leak: XPath context released with plain free() (wrong family).
 * xmlXPathNewContext's context must be released by xmlXPathFreeContext; the
 * generic free() is not a substitute (docs §6) and must NOT count as a
 * release — the context leaks.
 */

#include <stdlib.h>

typedef struct _xmlDoc xmlDoc;
typedef struct _xmlXPathContext xmlXPathContext;

extern xmlXPathContext *xmlXPathNewContext(xmlDoc *doc);

void tc155_xml_xpath_ctx_wrong_free(xmlDoc *doc) {
    xmlXPathContext *ctx = xmlXPathNewContext(doc);
    if (ctx == NULL) return;
    free(ctx);
}