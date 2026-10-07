/*
 * TC121 - GNU __attribute__ on a variable declarator between the name and the
 * initializer. tree-sitter-c v0.24.4 parses this by inserting an
 * attribute_specifier between the declarator and the value inside
 * init_declarator, which used to break every detector that read the
 * initializer by positional index NamedChildren()[1]. The detectors must still
 * see the initializer (malloc / NULL) despite the attribute.
 */

#include <stdlib.h>

void ml_attr_leak(void) {
    char *lp __attribute__((aligned(16))) = malloc(10);
    (void)lp;
}

void ns_attr_malloc(void) {
    int *p __attribute__((aligned(16))) = malloc(10);
    if (p != NULL) {
        *p = 1;
    }
}

void ns_attr_null(void) {
    int *p __attribute__((aligned(16))) = NULL;
    (void)p;
}
