/*
 * TC153 - Memory Leak: namespace attached to a node escapes with it.
 * xmlNewNs's namespace, once attached with xmlSetNs(node, ns), is managed
 * by the node's lifetime; the unconditional-transfer model must exempt it
 * from a standalone leak (docs §5.1A xmlNewNs lifecycle note).
 */

#include <stdlib.h>

typedef struct _xmlNode xmlNode;
typedef struct _xmlNs xmlNs;

extern xmlNs *xmlNewNs(xmlNode *node, const char *href, const char *prefix);
extern void xmlSetNs(xmlNode *node, xmlNs *ns);

void tc153_xml_ns_attach(xmlNode *node) {
    xmlNs *ns = xmlNewNs(node, "http://example.com", "ex");
    if (ns == NULL) return;
    xmlSetNs(node, ns);
}