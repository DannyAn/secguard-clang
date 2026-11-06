#include <stdint.h>

struct Conn {
    uint64_t id;
    uint64_t value;
};

extern struct Conn *conn_new(int version);

uint64_t conn_value(void)
{
    struct Conn *conn = (struct Conn *)conn_new(4);
    if (conn == NULL) {
        return 0;
    }
    return conn->value;
}
