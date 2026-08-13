#include <stdlib.h>

extern int RegSetValueExA(void *, const char *, unsigned long, unsigned long,
                          const void *, unsigned long);

void tc31_reg_set_value(void *hKey) {
    RegSetValueExA(hKey, "Password", 0, 0, (char*)"P@ssw0rd!", 9);
}
