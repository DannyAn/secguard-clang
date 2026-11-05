#include <stddef.h>

static int copy_field(unsigned char *dst,
                      size_t dst_len,
                      size_t header_len,
                      size_t payload_len)
{
    if (payload_len > dst_len - header_len) {
        return -1;
    }

    return (int)(dst + header_len)[payload_len - 1];
}
