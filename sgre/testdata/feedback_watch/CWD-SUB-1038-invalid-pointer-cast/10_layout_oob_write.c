#include <stdint.h>
#include <stdlib.h>

struct LargeRecord {
    uint64_t id;
    uint64_t flags;
    uint64_t value;
};

int write_record(void)
{
    unsigned char *raw = (unsigned char *)malloc(8);
    if (raw == NULL) {
        return -1;
    }

    struct LargeRecord *record = (struct LargeRecord *)raw;
    record->value = 42;

    free(raw);
    return 0;
}