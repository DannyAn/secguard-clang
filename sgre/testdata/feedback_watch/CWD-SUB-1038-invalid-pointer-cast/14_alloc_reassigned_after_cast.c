#include <stdint.h>
#include <stdlib.h>

struct LargeRecord {
    uint64_t id;
    uint64_t flags;
    uint64_t value;
};

uint64_t read_after_realloc(void)
{
    unsigned char *raw = (unsigned char *)malloc(64);
    if (raw == NULL) {
        return 0;
    }

    struct LargeRecord *record = (struct LargeRecord *)raw;
    raw = (unsigned char *)malloc(4);

    uint64_t result = record->value;

    free(record);
    return result;
}
