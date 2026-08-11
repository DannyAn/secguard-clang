---
name: crypto-misuse
description: Classify cryptographic misuse evidence — weak algorithms, weak PRNG, and undersized keys. Maps to CWE-327.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-327
  severity: HIGH
  domain: crypto
---

## Cryptographic Misuse Analysis (CWE-327)

### Evidence Patterns

#### Weak Algorithms (CWE-327)
- **CRYPTO_MISUSE event** with category `weak_cipher` / `weak_hash`
- DES/3DES for encryption (56-bit key, brute-forceable)
- MD5 or SHA1 for hashing (collision vulnerabilities)
- RC4 for encryption (biased keystream)

#### Weak PRNG (CWE-338)
- **CRYPTO_MISUSE event** with category `weak_prng`
- `rand()`, `random()` used for security-sensitive values (tokens, keys, nonces)
- Not cryptographically secure; predictable output

#### Undersized Keys (CWE-326)
- **CRYPTO_MISUSE event** with category `weak_key`
- RSA key < 2048 bits, AES key < 128 bits
- Insufficient entropy for the security level

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `EVP_aes_256_cbc()` / `EVP_aes_256_gcm()` | AES-256, industry standard |
| `SHA256()` / `SHA512()` / `EVP_sha3_256()` | Modern hash, no known collisions |
| `getrandom(buf, len, 0)` (Linux) | Cryptographic PRNG |
| `CryptGenRandom()` (Windows) | Cryptographic PRNG |
| `RAND_bytes()` (OpenSSL) | Cryptographic PRNG |
| RSA key ≥ 2048 bits | Adequate key size |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| DES/3DES used for encryption | **confirmed** |
| MD5/SHA1 used for security purposes | **confirmed** |
| RC4 used for encryption | **confirmed** |
| `rand()` / `random()` for tokens/keys/nonces | **confirmed** |
| `rand()` for non-security purposes (UI, testing) | **suspected** (verify context) |
| AES-256 via OpenSSL EVP | **false-positive** |
| SHA-256 / SHA-3 for hashing | **false-positive** |
| `getrandom()` / `RAND_bytes()` for random | **false-positive** |
| RSA key < 2048 bits | **confirmed** |
| RSA key ≥ 2048 bits | **false-positive** |

### Fix Suggestions
- DES/3DES → AES-256 (CBC or GCM mode)
- MD5 → SHA-256 or SHA-3; SHA1 → SHA-256 or SHA-3
- RC4 → AES-256
- `rand()` → `getrandom()` (Linux), `CryptGenRandom()` (Windows), `RAND_bytes()` (OpenSSL)
- Use keys of at least 128 bits (256 recommended for long-term security)
- RSA keys: minimum 2048 bits (3072 recommended for 2030+)
- Use vetted crypto libraries (OpenSSL, libsodium, BoringSSL) — never roll your own
- For hashing passwords: use bcrypt, scrypt, or Argon2 (not raw SHA-256)