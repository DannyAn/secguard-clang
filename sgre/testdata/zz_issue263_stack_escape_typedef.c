/* Issue #263 4.1 fixtures: a pointer-typedef (or cast) rename of a parameter
 * is NOT a local object — `&q->field` addresses the pointee, not this frame.
 * An opaque typedef base cannot be proven either way, so it is downgraded to
 * a suspected lead for the AI instead of being auto-confirmed.
 *
 * Expected:
 *   typedef_ptr_view  — NO candidate (q is a typedef-hidden pointer view)
 *   cast_view         — NO candidate (issue skeleton: cast rename of param)
 *   opaque_struct_esc — suspected, category return_stack_address_opaque,
 *                       base_kind opaque (the typedef target is not visible)
 *   real_local_escape — confirmed (control: genuine in-frame escape)
 *   plain_addr_escape — confirmed (control: &x addresses the local itself)
 */

struct inner263 {
    int field;
    int other;
};

typedef struct inner263 *inner_ptr263;

int *typedef_ptr_view(struct inner263 *param)
{
    inner_ptr263 q = param;
    return &q->field;
}

int *cast_view(struct inner263 *param)
{
    struct inner263 *q = (struct inner263 *)param;
    return &q->field;
}

typedef struct { int f; } opaque263_t;

int *opaque_struct_escape(void)
{
    opaque263_t s;
    s.f = 1;
    return &s.f;
}

int *real_local_escape(int x)
{
    struct inner263 local;
    local.field = x;
    return &local.field;
}

int *plain_addr_escape(void)
{
    int x;
    return &x;
}