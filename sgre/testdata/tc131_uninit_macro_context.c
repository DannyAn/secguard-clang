/*
 * TC131 - Uninit: a struct field written through an ALL_CAPS function-like macro
 * (HTONBUF, the nlog byte-order macro) is invisible to the flow model, so the
 * later field read would otherwise be "certain-uninit" and auto-confirmed. The
 * macro-context downgrade must keep it suspected (not confirmed).
 */

typedef struct { unsigned int hpfS6Addr32[4]; } ip6_t;

static ip6_t g_src;

unsigned int HTONBUF(unsigned int *dst, unsigned int src);

int use_ipv6(void) {
    ip6_t ipv6;
    HTONBUF(&ipv6.hpfS6Addr32[0], g_src.hpfS6Addr32[0]);
    return (int)ipv6.hpfS6Addr32[0];
}
