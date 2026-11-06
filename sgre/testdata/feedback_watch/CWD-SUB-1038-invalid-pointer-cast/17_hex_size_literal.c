#include <stdint.h>
#include <stdlib.h>

struct LargeRecord {
    uint64_t id;
    uint64_t flags;
    uint64_t value;
};

int read_hex_size(void)
{
    struct LargeRecord *record = (struct LargeRecord *)malloc(0x8U);
    if (record == NULL) {
        return -1;
    }

    int result = (int)record->value;

    free(record);
    return result;
}
