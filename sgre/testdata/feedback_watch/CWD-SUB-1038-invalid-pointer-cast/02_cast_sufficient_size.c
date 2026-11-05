#include <stdint.h>
#include <stdlib.h>

struct LargeRecord {
    uint64_t id;
    uint64_t flags;
    uint64_t value;
};

int read_record_safe(void)
{
    struct LargeRecord *record =
        (struct LargeRecord *)malloc(sizeof(struct LargeRecord));

    if (record == NULL) {
        return -1;
    }

    record->id = 1;
    record->flags = 0;
    record->value = 7;

    int result = (int)record->value;
    free(record);
    return result;
}
