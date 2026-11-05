#include <stddef.h>

static int read_byte_safe(const unsigned char *buffer,
                          size_t buffer_len,
                          size_t offset)
{
    if (buffer == NULL) {
        return -1;
    }

    if (offset >= buffer_len) {
        return -1;
    }

    return buffer[offset];
}

int main(void)
{
    unsigned char data[16] = {0};
    return read_byte_safe(data, sizeof(data), 5);
}
