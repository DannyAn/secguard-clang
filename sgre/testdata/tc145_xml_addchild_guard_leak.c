/*
 * TC145 - Memory Leak: guarded owning-add whose failure branch leaks.
 * `if (!xmlAddChild(parent, node)) return;` — the transfer happens only on
 * success; on the failure branch the caller still owns the node and returns
 * without releasing it. The leak must be reported, but as a CONDITIONAL
 * candidate (a transfer channel exists), never definite (docs §5.2C/§9.1:
 * the failure path must not be treated as unconditionally transferred).
 */

#include <stdlib.h>

typedef struct _xmlNode xmlNode;

extern xmlNode *xmlNewNode(xmlNode *ns, const char *name);
extern xmlNode *xmlAddChild(xmlNode *parent, xmlNode *cur);

int tc145_xml_addchild_guard_leak(xmlNode *parent) {
    xmlNode *node = xmlNewNode(NULL, "item");
    if (node == NULL) return -1;
    if (!xmlAddChild(parent, node)) {
        return -1;
    }
    return 0;
}