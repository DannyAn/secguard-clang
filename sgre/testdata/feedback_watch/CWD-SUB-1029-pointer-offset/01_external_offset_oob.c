#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static int read_byte(const unsigned char *buffer,
                     size_t buffer_len,
                     size_t external_offset)
{
    (void)buffer_len;
    return buffer[external_offset];
}

int main(int argc, char **argv)
{
    unsigned char data[16] = {0};
    size_t offset = (size_t)argc * 1024U;

    return read_byte(data, sizeof(data), offset);
}
