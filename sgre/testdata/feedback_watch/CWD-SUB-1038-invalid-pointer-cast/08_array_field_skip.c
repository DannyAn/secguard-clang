#include <stdint.h>
#include <stdlib.h>

struct ArrayRecord {
    uint64_t id;
    uint8_t buf[16];
    uint64_t value;
};

int read_array_field(void)
{
    unsigned char *raw = (unsigned char *)malloc(8);
    if (raw == NULL) {
        return -1;
    }

    struct ArrayRecord *record = (struct ArrayRecord *)raw;
    int result = (int)record->buf[0];

    free(raw);
    return result;
}