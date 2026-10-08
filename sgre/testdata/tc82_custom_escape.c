/*
 * TC82 - Memory Leak: Custom Ownership-Transfer Call (config-driven escape)
 * dict_set does not match the built-in IsEscapeFunction naming heuristic
 * (_put/_push/_add/...), so by default the pointer is reported as a leak.
 * After RegisterOwnershipTransfer("dict_set") (via secguard.toml
 * [ownership_transfer_calls]), the call is recognized as an escape and
 * the allocation is not leaked.
 */

#include <stdlib.h>

extern void dict_set(void *dict, void *val);

void tc82_custom_escape(void *d) {
    char *p = (char *)malloc(100);
    if (!p) return;
    dict_set(d, p);
}
