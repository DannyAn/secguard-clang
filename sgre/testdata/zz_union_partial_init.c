typedef union { int vlan; int id; int isBd; } vlan_u;
typedef struct { int a; int b; } pair_t;

int sink(int);

/* Issue #253 P2-1: writing one union member initializes the shared storage,
 * so reading a DIFFERENT member is not a partial-init defect. */
int union_member_write_read_other(void)
{
    vlan_u u;
    int x;
    int y;
    u.vlan = 1;
    x = u.id;
    y = u.isBd;
    return x + y;
}

/* Control: a struct is per-field — s.b really is uninitialized. */
int struct_member_write_read_other(void)
{
    pair_t s;
    int z;
    s.a = 1;
    z = s.b;
    return z;
}