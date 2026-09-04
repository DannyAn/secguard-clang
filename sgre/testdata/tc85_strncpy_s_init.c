typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

#define MAX_NAME_LEN 64
#define NAME_LEN 64

typedef struct {
    uint32_t cmd;
    uint16_t pool_id;
    uint16_t vsys_id;
    char pool_name[MAX_NAME_LEN];
} pool_ipc_create_t;

void ipc_send(void *msg);
void use_name(const char *name);

/* strncpy_s writes msg.pool_name (the destination field) — not a read-before-init.
 * The struct is filled field-by-field, so msg must not be reported. */
void pool_send_filled(uint16_t pool_id, uint16_t id, const char *pool_name) {
    pool_ipc_create_t msg;
    msg.cmd = 1;
    msg.pool_id = pool_id;
    msg.vsys_id = id;
    (void)strncpy_s(msg.pool_name, MAX_NAME_LEN, pool_name, NAME_LEN - 1);
    ipc_send(&msg);
}

/* A whole array filled by strncpy_s is likewise a write, not a read. */
void whole_array_filled(const char *src) {
    char name[MAX_NAME_LEN];
    (void)strncpy_s(name, MAX_NAME_LEN, src, NAME_LEN - 1);
    ipc_send(name);
}

/* A field never written stays genuinely uninitialized when read. */
void field_never_init(void) {
    pool_ipc_create_t bad_msg;
    bad_msg.cmd = 1;
    bad_msg.vsys_id = 2;
    use_name(bad_msg.pool_name); /* bad_msg.pool_name never written → struct_partial_uninit */
}
