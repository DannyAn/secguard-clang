#include <stdlib.h>

typedef struct { int x; } my_struct_t;

extern int ext_int_func(int arg);
extern my_struct_t *ext_ptr_func(int arg);
extern void ext_void_func(int arg);

void use_external_int(void)
{
    int v = ext_int_func(42);
    (void)v;
}

void use_external_ptr(void)
{
    my_struct_t *p = ext_ptr_func(42);
    p->x = 1;
}

void use_external_void(void)
{
    ext_void_func(42);
}