# Crypto Misuse in generate_token_weak

**CWE:** CWE-327

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/crypto.c:30`
- **Function:** `generate_token_weak`
- **Variable:** `rand()`

## Evidence

- **crypto_misuse:** weak crypto in generate_token_weak at line 30
- **call_path:** function generate_token_weak is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Replace the weak cryptographic primitive in `generate_token_weak` with a modern,
industry-standard alternative:

```c
// BAD:  DES_set_key_unchecked(&key, &schedule);
// GOOD: use AES-256 via a vetted library (OpenSSL EVP)
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
```

Specific replacements: DES/3DES → AES-256; MD5/SHA1 → SHA-256 or SHA-3;
rand() → cryptographic PRNG (getrandom, CryptGenRandom); RC4 → AES.
Use keys of at least 128 bits (256 recommended for long-term security).
