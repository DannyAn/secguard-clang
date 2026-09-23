#include <stdlib.h>
#include <stdint.h>

#define MID_SEC_ID 1
#define ERR 1
#define OK 0

typedef unsigned int uint32_t;

struct leaf_s { int x; };
struct com_s { uint32_t num; struct leaf_s *leafs; };
typedef struct com_s struct_com_t;

typedef struct node_s struct_node_t;
typedef struct parser_s struct_parser_t;

void *xlog_malloc(int id, uint32_t size) { return malloc(size); }
void *nlog_malloc(int id, uint32_t size) { return malloc(size); }

uint32_t case1_struct_init_child_parser(struct_node_t *parent, struct_parser_t *parser, uint32_t num)
{
    if (parent == NULL || parser == NULL) {
        return ERR;
    }
    struct com_s nodes = {.num = num};
    uint32_t size = sizeof(*nodes.leafs) * nodes.num;
    typeof(nodes.leafs) leafs = (typeof(nodes.leafs))xlog_malloc(MID_SEC_ID, size);
    if (leafs == NULL) {
        return ERR;
    }
    leafs->x = 0;
    return OK;
}

uint32_t case2_xlog_malloc_topn_data(char **topn, uint32_t len)
{
    *topn = (typeof(*topn))xlog_malloc(MID_SEC_ID, len);
    if (*topn == NULL) {
        return ERR;
    }
    return OK;
}

struct addrinfo_s { int ai_flags; struct addrinfo_s *ai_next; };
typedef struct addrinfo_s addrinfo_t;

uint32_t case3_kafka_dns_fill(addrinfo_t **res, uint32_t socklen)
{
    addrinfo_t *ai = NULL;
    ai = *res = xlog_malloc(MID_SEC_ID, sizeof(addrinfo_t) + socklen);
    if (ai == NULL) {
        return ERR;
    }
    ai->ai_flags = 0;
    return OK;
}

struct thrt_info_s { int data; };
typedef struct thrt_info_s thrt_info_t;
typedef struct { thrt_info_t *thrt_normal_string_info; } thrt_org_t;

void case5_set_thrt_comm(thrt_org_t *thrt_log)
{
    thrt_log->thrt_normal_string_info = (typeof(thrt_log->thrt_normal_string_info))
        nlog_malloc(MID_SEC_ID, sizeof(*thrt_log->thrt_normal_string_info));
    if (thrt_log->thrt_normal_string_info == NULL) {
        return;
    }
    thrt_log->thrt_normal_string_info->data = 0;
}

uint32_t case6___typeof(struct com_s *nodes, uint32_t size)
{
    __typeof(nodes->leafs) leafs = (__typeof(nodes->leafs))xlog_malloc(MID_SEC_ID, size);
    if (leafs == NULL) {
        return ERR;
    }
    leafs->x = 0;
    return OK;
}

uint32_t case7___typeof__(struct com_s *nodes, uint32_t size)
{
    __typeof__(nodes->leafs) leafs = (__typeof__(nodes->leafs))xlog_malloc(MID_SEC_ID, size);
    if (leafs == NULL) {
        return ERR;
    }
    leafs->x = 0;
    return OK;
}

uint32_t case8_typeof_unqual(struct com_s *nodes, uint32_t size)
{
    typeof_unqual(nodes->leafs) leafs = (typeof_unqual(nodes->leafs))xlog_malloc(MID_SEC_ID, size);
    if (leafs == NULL) {
        return ERR;
    }
    leafs->x = 0;
    return OK;
}

void positive_control(void) {
    char *p = malloc(100);
    p[0] = 'x';
}
typedef struct { int x; } spec_t;
typedef int (*gen_fn)(spec_t *spec);

gen_fn storage_spec_gx_get_maf_origin_log_allocate_size;
gen_fn storage_spec_gx_get_maf_report_log_allocate_size;

void storage_spec_generator_log_allocate_size_init(spec_t *spec)
{
    spec->x = 0;
}

void case4_storage_cap_attri_init(void)
{
    spec_t spec;
    storage_spec_generator_log_allocate_size_init(&spec);
}