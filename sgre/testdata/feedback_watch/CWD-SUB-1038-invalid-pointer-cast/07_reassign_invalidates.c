#include <stdint.h>
#include <stdlib.h>

struct LargeRecord {
    uint64_t id;
    uint64_t flags;
    uint64_t value;
};

int read_reassigned(void)
{
    unsigned char *raw = (unsigned char *)malloc(8);
    if (raw == NULL) {
        return -1;
    }

    struct LargeRecord *record = (struct LargeRecord *)raw;
    record = (struct LargeRecord *)malloc(sizeof(struct LargeRecord));
    if (record == NULL) {
        free(raw);
        return -1;
    }

    int result = (int)record->value;
    free(record);
    free(raw);
    return result;
}