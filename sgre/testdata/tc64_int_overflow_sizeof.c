#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void safe_sizeof_alloc(int n) {
    char *p = malloc(n * sizeof(int)); /* safe on LP64: sizeof promotes to size_t (64-bit) */
    if (p == NULL) return;
    free(p);
}

void safe_var_var_alloc(int m, int n) {
    char *p = malloc(m * n); /* INTEGER_OVERFLOW: two-variable product */
    if (p == NULL) return;
    free(p);
}

void safe_constant_alloc(void) {
    char *p = malloc(256); /* safe: constant */
    if (p == NULL) return;
    free(p);
}

void narrow_u32_product(uint32_t m, uint32_t n) {
    /* INTEGER_OVERFLOW: uint32_t * uint32_t is evaluated in 32-bit unsigned and
     * wraps; the wrapped value reaches malloc. The LP64 size_t result does NOT
     * make the multiplication 64-bit. */
    char *p = malloc(m * n);
    if (p == NULL) return;
    free(p);
}

void narrow_u16_product(uint16_t m, uint16_t n) {
    /* INTEGER_OVERFLOW: uint16_t promotes to int; 65535^2 overflows INT_MAX. */
    char *p = malloc(m * n);
    if (p == NULL) return;
    free(p);
}

void narrow_u8_product(uint8_t m, uint8_t n) {
    /* safe: 255*255 = 65025 fits in int after promotion. */
    char *p = malloc(m * n);
    if (p == NULL) return;
    free(p);
}

void narrow_u8_u16_product(uint8_t m, uint16_t n) {
    /* safe: 255*65535 = 16711425 fits in int after promotion. */
    char *p = malloc(m * n);
    if (p == NULL) return;
    free(p);
}
