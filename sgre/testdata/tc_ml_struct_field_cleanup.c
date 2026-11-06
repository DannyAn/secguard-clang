/*
 * TC - Memory Leak: struct field store + cleanup-by-address (Issue #241 mode C)
 * The IPsec idiom: allocate into a local struct field, then call a project
 * cleanup helper that takes the struct by address and releases every field.
 *   struct S s; s.field = malloc(n); ... cleanup(&s);
 * The tracked varName is the struct base "s" (the LHS field_expression's
 * first identifier). The cleanup call's argument is &s, so argIdentifier
 * must unwrap the address-of to match "s" — otherwise every such site is a
 * false-positive memory-leak.
 */

#include <stdlib.h>

struct S241 {
    unsigned int *field;
};

extern void cleanup_s241(struct S241 *s);

void tc_ml_struct_field_cleanup(void) {
    struct S241 s;
    s.field = (unsigned int *)malloc(100);
    if (!s.field) return;
    s.field[0] = 42;
    cleanup_s241(&s);
}