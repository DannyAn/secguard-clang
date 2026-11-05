#include <stdint.h>
#include <stdlib.h>

struct Record {
    uint64_t id;
    uint64_t value;
};

int make_records(size_t count)
{
    unsigned char *raw = (unsigned char *)malloc(count);
    if (raw == NULL) {
        return -1;
    }

    struct Record *records = (struct Record *)raw;

    records[count - 1].value = 1;

    free(raw);
    return 0;
}
