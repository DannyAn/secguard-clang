/*
 * TC157 - Memory Leak: xmlNewNode never released, never attached.
 * The node is neither freed with xmlFreeNode/xmlFreeNodeList nor attached
 * to a tree — a definite leak candidate with no channel at all (docs §5.1).
 */

#include <stdlib.h>

typedef struct _xmlNode xmlNode;

extern xmlNode *xmlNewNode(xmlNode *ns, const char *name);

void tc157_xml_newnode_leak(void) {
    xmlNode *node = xmlNewNode(NULL, "orphan");
    if (node == NULL) return;
}