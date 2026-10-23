/* tc119_deref_read_assign.c — NP-04 regression: a dereference-read assignment
 * (`T *r = *(T **)msg;`) must seed a may-null deref_read source for the lhs. */
typedef struct { int f; } T;

void proc(void *msg) {
    T *r = *(T **)msg;
    r->f = 1;
}

void call(void *x) { proc(x); }