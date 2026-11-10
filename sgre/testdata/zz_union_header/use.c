#include "types.h"

int sink(int);

int header_union_member_write_read_other(void)
{
    vlan_u u;
    int x;
    int y;
    u.vlan = 1;
    x = u.id;
    y = u.isBd;
    return x + y;
}

int header_struct_member_write_read_other(void)
{
    pair_t s;
    int z;
    s.a = 1;
    z = s.b;
    return z;
}
