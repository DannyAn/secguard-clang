#include <stddef.h>

static int read_byte_bad(const unsigned char *buffer,
                         size_t buffer_len,
                         size_t packet_len,
                         size_t offset)
{
    (void)buffer_len;

    if (offset >= packet_len) {
        return -1;
    }

    return buffer[offset];
}

int main(void)
{
    unsigned char data[8] = {0};
    size_t packet_len = 4096;
    size_t offset = 1024;

    return read_byte_bad(data, sizeof(data), packet_len, offset);
}
