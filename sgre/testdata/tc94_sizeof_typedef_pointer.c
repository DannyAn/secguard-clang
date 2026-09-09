#include <stdlib.h>
#include <string.h>

typedef char *cstr_t;
typedef unsigned int uint_t;

char *g_buf;

void typedef_pointer(cstr_t s) {
    char *p = malloc(sizeof(s)); /* typedef'd pointer: flagged (ambig) */
    (void)p;
    (void)s;
}

void typedef_deref(cstr_t s) {
    char *p = malloc(sizeof(*s)); /* sizeof(*s)=sizeof(char): correct, NOT flagged */
    (void)p;
    (void)s;
}

void explicit_pointer(char *q) {
    char *p = malloc(sizeof(q)); /* explicit `*`: flagged (confirmed) */
    (void)p;
    (void)q;
}

void non_pointer_typedef(uint_t n) {
    char *p = malloc(sizeof(n)); /* non-pointer typedef: correct, NOT flagged */
    (void)p;
    (void)n;
}

void file_scope_pointer(void) {
    char *p = malloc(sizeof(g_buf)); /* file-scope char*: flagged */
    (void)p;
    memset(g_buf, 0, sizeof(*g_buf)); /* sizeof(*g_buf): correct, NOT flagged */
}
