#include <stdint.h>
#include <stdlib.h>

struct BitfieldRecord {
    uint64_t id : 32;
    uint64_t flags : 32;
    uint64_t value;
};

int read_bitfield(void)
{
    unsigned char *raw = (unsigned char *)malloc(8);
    if (raw == NULL) {
        return -1;
    }

    struct BitfieldRecord *record = (struct BitfieldRecord *)raw;
    int result = (int)record->value;

    free(raw);
    return result;
}