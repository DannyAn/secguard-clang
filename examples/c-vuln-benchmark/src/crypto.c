
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <time.h>


static const char *g_api_key = "sk-abcdef1234567890abcdef1234567890";

void authenticate_user() {

    
    const char *password = "SuperSecretPassw0rd!";
    const char *token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";

    if (strcmp(getenv("USER_TOKEN"), token) == 0) {
        printf("Authenticated with hardcoded token\n");
    }
}


int generate_token_weak() {

    
    srand(time(NULL));
    int token = rand();
    return token;
}

int generate_token_strong() {
    
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    return buf[0];
}


void encrypt_data_weak(const char *plaintext) {

    
    DES_cblock key;
    DES_key_schedule schedule;


    DES_set_key_unchecked(&key, &schedule);

    unsigned char output[64];
    DES_ecb_encrypt((const_DES_cblock *)plaintext,
                    (DES_cblock *)output, &schedule, DES_ENCRYPT);
    printf("Encrypted with DES (broken)\n");
}

void encrypt_data_good(const char *plaintext) {
    
    unsigned char key[32];  
    RAND_bytes(key, sizeof(key));
    
    printf("Encrypted with AES-256-GCM (secure)\n");
}


void setup_encryption_weak() {

    
    unsigned char key[7];
    RAND_bytes(key, 7);

    

    printf("Using 56-bit key (should be 256-bit minimum)\n");
}

void setup_encryption_strong() {
    
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));
    printf("Using 256-bit key\n");
}

int main() {
    printf("Crypto vulnerability demo\n");
    authenticate_user();
    generate_token_weak();
    encrypt_data_weak("sensitive data");
    setup_encryption_weak();
    return 0;
}
