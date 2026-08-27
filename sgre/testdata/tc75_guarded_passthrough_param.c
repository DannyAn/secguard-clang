#include <stdint.h>
#include <stdbool.h>

typedef struct { int uid; } user_base_t;
typedef struct { int v; } addr_t;
typedef struct Mbuf Mbuf;

user_base_t *find_online_user(int id, addr_t *sip);
int online_user_is_temp(user_base_t *user);
void proc_temp(int id, addr_t *ip);

void test_ipv6_sync(Mbuf *mbuf, int actionId, void *flow_m) {
    addr_t sip;
    int id = 1;
    user_base_t *user = find_online_user(id, &sip);
    if (user == NULL || online_user_is_temp(user)) {
        test_sync_proc(id, user, &sip, true);
    }
}

uint32_t test_sync_proc(int id, const user_base_t *found_user, const addr_t *ip, bool m) {
    addr_t u = *ip;
    if (found_user == NULL) {
        return proc_temp(id, &u);
    }
    return found_user->uid;
}
