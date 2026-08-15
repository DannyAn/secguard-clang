#include <stdlib.h>

typedef struct { unsigned short version; unsigned short flag; } FileInfo;

/* getShort writes to its pointer param (output-param). */
unsigned short getShort(void *p) {
    *(unsigned short *)p = 0;
    return 0;
}

/* info is filled field-by-field through &info.field output-params, so neither
 * the whole struct nor its fields are uninitialized. */
int FieldOutputParam(void) {
    FileInfo info;
    getShort(&info.version);
    getShort(&info.flag);
    return info.version + info.flag;
}
