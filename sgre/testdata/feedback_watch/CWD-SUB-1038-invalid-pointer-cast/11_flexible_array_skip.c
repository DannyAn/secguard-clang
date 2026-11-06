#include <stdint.h>
#include <stdlib.h>

struct FlexRecord {
    uint32_t kind;
    uint8_t payload[];
};

int read_flex(void)
{
    struct FlexRecord *record = (struct FlexRecord *)malloc(4);
    if (record == NULL) {
        return -1;
    }

    int result = (int)record->payload[0];

    free(record);
    return result;
}
