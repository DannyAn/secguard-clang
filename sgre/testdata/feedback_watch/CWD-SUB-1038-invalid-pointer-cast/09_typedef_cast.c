#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint64_t id;
    uint64_t flags;
    uint64_t value;
} MyRecord;

int read_typedef(void)
{
    unsigned char *raw = (unsigned char *)malloc(8);
    if (raw == NULL) {
        return -1;
    }

    MyRecord *record = (MyRecord *)raw;
    int result = (int)record->value;

    free(raw);
    return result;
}