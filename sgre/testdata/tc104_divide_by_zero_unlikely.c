typedef unsigned int uint32_t;

struct Entry {
    uint32_t connNum;
    uint32_t curTcpProbeConnIndex;
    uint32_t curProbeIndex;
    uint32_t curConnIndex;
};

#define unlikely(x) __builtin_expect(!!(x), 0)
#define RC_CONTINUE 1
#define RC_NO_CONTINUE 0

uint32_t f(struct Entry *entry, uint32_t probeCount) {
    if (unlikely(entry == NULL)) {
        return RC_CONTINUE;
    }

    uint32_t curConnNum = entry->connNum;
    if (unlikely(curConnNum == 0)) {
        return RC_NO_CONTINUE; /* curConnNum == 0 → return, so below it is non-zero */
    }

    uint32_t loopIndex = (entry->curTcpProbeConnIndex) % curConnNum; /* 误报点 */
    return loopIndex;
}

uint32_t g(uint32_t d) {
    return 100 / d; /* 无守卫：真实疑似除零，应保留 */
}

