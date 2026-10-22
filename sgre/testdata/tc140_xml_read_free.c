/*
 * TC140 - Memory Leak: libxml2 document parse paired with xmlFreeDoc.
 * xmlReadMemory is a modeled libxml2 allocator (docs §5.1): it returns a
 * maybe-NULL xmlDoc that must be released by xmlFreeDoc on every path.
 * Correct pairing must NOT be reported as a leak.
 */

#include <stdlib.h>

typedef struct _xmlDoc xmlDoc;

extern xmlDoc *xmlReadMemory(const char *buf, int size, const char *url,
                             const char *enc, int opts);
extern void xmlFreeDoc(xmlDoc *doc);

void tc140_xml_read_free(const char *buf, int size) {
    xmlDoc *doc = xmlReadMemory(buf, size, NULL, NULL, 0);
    if (doc == NULL) return;
    xmlFreeDoc(doc);
}