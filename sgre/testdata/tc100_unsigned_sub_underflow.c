#include <stdint.h>

void consume(uint32_t value);

void unsigned_sub_param(uint32_t service_cnt, uint32_t *query_cnt) {
    consume(service_cnt - (*query_cnt));
}

void unsigned_sub_subscript(uint32_t service_cnt, uint32_t query_cnt[]) {
    consume(service_cnt - query_cnt[0]);
}

void unsigned_sub_guarded(uint32_t service_cnt, uint32_t *query_cnt) {
    if (*query_cnt <= service_cnt) {
        consume(service_cnt - (*query_cnt));
    }
}

void signed_sub(int service_cnt, int *query_cnt) {
    consume(service_cnt - (*query_cnt));
}

void unsigned_sub_constant(uint32_t service_cnt) {
    consume(service_cnt - 1);
}

void unsigned_sub_same(uint32_t service_cnt) {
    consume(service_cnt - service_cnt);
}
