#define LCORE_FOREACH_SLAVE(x) for ((x) = 0; (x) < 4; (x)++)

static int g(int id) { return 0; }

int f(int a, int b) {
    int ret;
    int lcoreId = 0;
    if (a | b) {
        LCORE_FOREACH_SLAVE(lcoreId) {
            ret = g(lcoreId);
            if (ret != 0) {
                return -1;
            }
        }
    }
    return 0;
}
