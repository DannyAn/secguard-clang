#include <stdlib.h>

void tc29_crypto_misuse() {
    srand(12345);
    int token = rand();
}