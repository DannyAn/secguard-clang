#include "types.h"
#include <stdlib.h>

/* my_uint resolves to `unsigned int` ONLY via types.h. Without cross-file
 * typedef resolution this comparison is missed; with it, the detector must
 * flag it as always-false dead logic. */
int unsafe_unsigned_typedef(my_uint m) {
    if (m < 0) { /* SIGNED_COMPARE: my_uint -> unsigned int */
        return 1;
    }
    return 0;
}

/* cstr_t resolves to `char *` ONLY via types.h, so `cstr_t *s` is a
 * pointer-to-pointer (char **). sizeof(s) sizes the pointer array, which is
 * legitimate — the detector must NOT over-confidently flag it as CWE-467, only
 * as the ambiguous/suspected category. */
void ambig_sizeof_pointer_typedef(int n) {
    cstr_t *s = malloc(n * sizeof(s)); /* SIZEOF_MISUSE: sizeof_pointer_ambig */
}

/* my_uint *p is a plain pointer whose base (my_uint) is NOT a pointer, so
 * sizeof(p) is the classic CWE-467 defect — provable, hence confirmed. The base
 * resolution of my_uint comes from the header. */
void confirmed_sizeof_header_typedef(int n) {
    my_uint *p = malloc(n * sizeof(p)); /* SIZEOF_MISUSE: sizeof_pointer */
}
