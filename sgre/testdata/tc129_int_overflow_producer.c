#include <stdint.h>

void consume(uint32_t value);

uint32_t ase_sa_str_connect(char *buf, uint32_t max_len, const char *fmt, const char *s) {
    (void)buf;
    (void)fmt;
    (void)s;
    return max_len > 0 ? 1 : 0;
}

void unsigned_sub_producer(uint32_t max_len, char *buf, const char *s) {
    uint32_t len = 0;
    len += ase_sa_str_connect(buf, max_len - len, "%s", s);
    consume(max_len - len);
}

void unsigned_sub_no_producer(uint32_t max_len, uint32_t used) {
    consume(max_len - used);
}
