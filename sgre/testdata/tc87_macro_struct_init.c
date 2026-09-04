typedef unsigned int uint32_t;

typedef struct {
    uint32_t field;
    uint32_t other;
} foo_t;

/* Field-setter macro: writes s.field (a member), not the whole s. */
#define SET_FIELD(s, v) ((s).field = (v))

/* Whole-struct zeroing macro: memsets the whole s. */
#define ZERO(s) memset(&(s), 0, sizeof(s))

void use_foo(const foo_t *f);
void use_field(uint32_t v);

/* SET_FIELD initializes x.field; x.other is assigned directly. */
void field_setter_macro(void) {
    foo_t x;
    SET_FIELD(x, 1);
    x.other = 2;
    use_foo(&x);
}

/* ZERO initializes all of x. */
void whole_struct_macro(void) {
    foo_t x;
    ZERO(x);
    use_foo(&x);
}

/* A field never written stays flagged. */
void field_never_written(void) {
    foo_t bad;
    bad.field = 1;
    use_field(bad.other);
}
