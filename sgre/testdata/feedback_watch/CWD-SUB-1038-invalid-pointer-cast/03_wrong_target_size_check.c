#include <stdint.h>
#include <stdlib.h>

struct SmallHeader {
    uint32_t type;
};

struct LargeRecord {
    uint64_t id;
    uint64_t flags;
    uint64_t value;
};

int parse_record(size_t input_len)
{
    unsigned char *raw = (unsigned char *)malloc(input_len);
    if (raw == NULL) {
        return -1;
    }

    if (input_len < sizeof(struct SmallHeader)) {
        free(raw);
        return -1;
    }

    struct LargeRecord *record = (struct LargeRecord *)raw;
    int result = (int)record->value;

    free(raw);
    return result;
}
