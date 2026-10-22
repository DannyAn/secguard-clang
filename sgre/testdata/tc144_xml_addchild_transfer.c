/*
 * TC144 - Memory Leak: node ownership transferred to the parent tree.
 * xmlNewNode's result is attached with xmlAddChild(parent, node) and the
 * return value is NOT checked: the owning-add contract (success takes the
 * node) applies on the unchecked form, so the node is not a leak — it rides
 * with the parent's lifetime (docs §5.1C).
 */

#include <stdlib.h>

typedef struct _xmlNode xmlNode;

extern xmlNode *xmlNewNode(xmlNode *ns, const char *name);
extern xmlNode *xmlAddChild(xmlNode *parent, xmlNode *cur);

void tc144_xml_addchild_transfer(xmlNode *parent) {
    xmlNode *node = xmlNewNode(NULL, "item");
    if (node == NULL) return;
    xmlAddChild(parent, node);
}