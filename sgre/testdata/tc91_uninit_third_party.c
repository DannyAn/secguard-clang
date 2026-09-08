/*
 * TC91 - Uninit: third-party out-param writers (cast &x / setter macro).
 * These are false positives to suppress:
 *   - s1: `(VOS_UINT32 *)&time_ut` passes &time_ut through a cast to an
 *         out-param writer (third-party VOS_Tm_NowInSec).
 *   - s2: `(void *)&(dst_ipv6)` passes &dst_ipv6 (cast + parens) to inet_pton.
 *   - s3: `ODA_GPORT_TRUNK_SET(gport, trunkid)` is a setter MACRO whose body
 *         lives in an excluded header, so only its `_SET` name signals it
 *         writes its first argument.
 * Expected: NO VALUE_USE event.
 */

typedef unsigned int uint32_t;
typedef unsigned long DULONG;
typedef unsigned long VOS_UINT32;
typedef struct { unsigned char x[16]; } HpfIn6Addr;
typedef unsigned int oda_gport_t;

int tc91_s1_cast_addr(void) {
    uint32_t time_ut;
    VOS_Tm_NowInSec((VOS_UINT32 *)&time_ut);
    return (int)time_ut;
}

int tc91_s2_paren_cast_addr(void) {
    HpfIn6Addr dst_ipv6;
    char ipv6_str[64];
    int ret = inet_pton(2, ipv6_str, (void *)&(dst_ipv6));
    return ret;
}

int tc91_s3_setter_macro(void) {
    oda_gport_t gport;
    unsigned int trunkid = 1;
    ODA_GPORT_TRUNK_SET(gport, trunkid);
    return (int)gport;
}
