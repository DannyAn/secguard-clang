#define NULL ((void *)0)

struct Nat66Info { int natIp6; int natPort; int natType; };
struct Public { int srcNat; };
struct Flow { int dummy; };

void *GetVarInfo(struct Public *p, int off);
void Ipv6FlowSetNat66SrcInfo(struct Flow *flow, void *ip, int port, int type);

void fill_info(struct Flow *flow, struct Public *v5_flow_public) {
    struct Nat66Info *v5_nat66_info = NULL;
    if (v5_flow_public->srcNat) {
        v5_nat66_info = (struct Nat66Info *)GetVarInfo(v5_flow_public, v5_flow_public->srcNat);
        Ipv6FlowSetNat66SrcInfo(flow, &v5_nat66_info->natIp6, v5_nat66_info->natPort, v5_nat66_info->natType);
    }
}

void certain_null(struct Public *p) {
    struct Nat66Info *v = NULL;
    int x = v->natIp6; /* 无重赋值：真实 certain null-deref */
}
