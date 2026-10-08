#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct { int x; } my_struct_t;

extern my_struct_t *ext_ptr_func(int arg);

void use_maybe_null_libc(void)
{
    char buf[] = "hello";
    char *p = strchr(buf, 'x');
    *p = 'X';
}

void use_never_null_libc(void)
{
    char *s = strerror(42);
    *s = 'X';
}

void use_unknown_external(void)
{
    my_struct_t *p = ext_ptr_func(42);
    p->x = 1;
}