#include <string.h>

void tc27_hardcoded_secret() {
    const char *password = "SuperSecretPassw0rd!";
    const char *api_key = "sk-abcdef1234567890abcdef1234567890";
    if (strcmp(password, api_key) == 0) {
        return;
    }
}