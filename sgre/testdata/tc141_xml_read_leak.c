/*
 * TC141 - Memory Leak: libxml2 document never released and never transferred.
 * xmlReadMemory's result is a caller-owned xmlDoc with no free and no
 * ownership hand-off on any path: a leak candidate must be reported.
 */

#include <stdlib.h>

typedef struct _xmlDoc xmlDoc;

extern xmlDoc *xmlReadMemory(const char *buf, int size, const char *url,
                             const char *enc, int opts);

void tc141_xml_read_leak(const char *buf, int size) {
    xmlDoc *doc = xmlReadMemory(buf, size, NULL, NULL, 0);
    if (doc == NULL) return;
}