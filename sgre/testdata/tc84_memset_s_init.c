typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

typedef struct {
    uint16_t vrfIndex;
} FlowDetail;

typedef struct {
    FlowDetail detail;
} FlowKey;

typedef struct {
    struct {
        uint32_t src_ip;
        uint32_t vrf_index;
        uint32_t zone;
    } basic_info;
} map_nopat_t;

void *FlowGetKey(void *flow, void *key);
uint32_t FlowGetSrcIp(void *flow);
uint32_t FlowGetOutZone(void *flow);

/* memset_s clears the whole key_info struct, then FlowGetKey fills it; the
 * later field read is definitely initialized. */
void sec_sess_refresh_update(void *flow) {
    map_nopat_t map_param;
    FlowKey key_info;
    (void)memset_s(&key_info, sizeof(key_info), 0, sizeof(key_info));
    (void)memset_s(&map_param, sizeof(map_nopat_t), 0, sizeof(map_nopat_t));

    FlowGetKey(flow, &key_info);
    map_param.basic_info.src_ip = FlowGetSrcIp(flow);
    map_param.basic_info.vrf_index = key_info.detail.vrfIndex;
    map_param.basic_info.zone = FlowGetOutZone(flow);
}

/* A struct never passed to an initializer remains genuinely uninitialized. */
uint16_t partial_memset_s(void *flow) {
    FlowKey uninit_key;
    FlowGetKey(flow, &uninit_key);
    return uninit_key.detail.vrfIndex; /* vrfIndex never initialized */
}