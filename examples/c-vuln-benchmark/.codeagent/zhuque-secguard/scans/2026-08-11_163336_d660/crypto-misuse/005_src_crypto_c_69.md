# Crypto Misuse in authenticate_user

**CWE:** CWE-327

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/crypto.c:69`
- **Function:** `authenticate_user`

## Evidence

- **crypto_misuse:** weak crypto in authenticate_user at line 69
- **call_path:** function authenticate_user is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Replace the weak cryptographic primitive in `authenticate_user` with a modern,
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
