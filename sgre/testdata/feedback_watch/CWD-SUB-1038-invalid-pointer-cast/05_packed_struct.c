#include <stdint.h>
#include <stdlib.h>

struct PackedRecord {
    uint8_t tag;
    uint64_t value;
} __attribute__((packed));

int read_packed(void)
{
    unsigned char *raw = (unsigned char *)malloc(8);
    if (raw == NULL) {
        return -1;
    }

    struct PackedRecord *record = (struct PackedRecord *)raw;
    int result = (int)record->value;

    free(raw);
    return result;
}