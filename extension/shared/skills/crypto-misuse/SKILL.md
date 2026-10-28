---
name: crypto-misuse
description: Classify cryptographic misuse evidence — weak algorithms, weak PRNG, and undersized keys. Maps to CWE-327.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-327
  severity: HIGH
  domain: security
---

## Cryptographic Misuse Analysis (CWE-327)

### Evidence Patterns

#### Weak Algorithms (CWE-327)
- **CRYPTO_MISUSE event** with category `weak_algorithm`
- DES/3DES for encryption (56-bit key, brute-forceable)
- MD5 or SHA1 for hashing (collision vulnerabilities)
- RC4 for encryption (biased keystream)

#### Weak PRNG (CWE-338)
- **CRYPTO_MISUSE event** with category `weak_random`
- `rand()`, `random()` used for security-sensitive values (tokens, keys, nonces)
- Not cryptographically secure; predictable output

#### Undersized Keys (CWE-326)
- **CRYPTO_MISUSE event** with category `undersized_key`
- RSA key < 2048 bits, AES key < 128 bits
- Insufficient entropy for the security level

Evidence file fragments:
- **crypto_misuse**: the site with the detector's reason (e.g. "MD5 is cryptographically broken", "weak PRNG for security context")
- **key_size**: the declared key size in bytes (undersized-key category)
- **call_path**: the function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `reason@<text>` | the detector's observed weakness (e.g. "DES is weak (56-bit key)", "MD5 is cryptographically broken", "weak PRNG for security context") | judge from THIS text, not from the API name alone — it is the detector's rationale, already category-specific |
| `key-size@N` | the declared key size in bytes | N < 16 (128 bits) is below the modern-cipher minimum — confirm as undersized |

A `reason@` token alone (no `key-size@`) is the weak_algorithm / weak_random
shape: the primitive itself is broken regardless of call context, so the row is
settled from the Hint — no evidence-file open needed.

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `EVP_aes_256_cbc()` / `EVP_aes_256_gcm()` | AES-256, industry standard |
| `SHA256()` / `SHA512()` / `EVP_sha3_256()` | Modern hash, no known collisions |
| `getrandom(buf, len, 0)` (Linux) | Cryptographic PRNG |
| `CryptGenRandom()` (Windows) | Cryptographic PRNG |
| `RAND_bytes()` (OpenSSL) | Cryptographic PRNG |
| RSA key ≥ 2048 bits | Adequate key size |

### Evidence closure (read before any source read)

The candidate file already embeds the decisive cross-file facts the pipeline
resolved: an in-scan callee body under `## Callee Definition` (Hint
`callee@<file>:<line>`) and project macro bodies under `## Macro Definition`
(Hint `macro@<name>`). Read those sections first — they are in-file and cost no
lookup. Only a fact that is NOT embedded may be resolved with `secguard_def` /
`secguard def <symbol>` (batch related symbols); never grep the repository for a
definition, and never dismiss a macro/callee as "out of scan" before checking
the embedded section and the indexed lookup.

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| DES/3DES used for encryption | **confirmed** |
| MD5/SHA1 used for security purposes | **confirmed** |
| RC4 used for encryption | **confirmed** |
| `rand()` / `random()` for tokens/keys/nonces | **confirmed** |
| `rand()` for non-security purposes (UI, testing) | **dismissed** (verify context) |
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

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Weak hash (MD5/SHA-1) for password storage / verification | CRITICAL |
| Weak algorithm (DES/3DES/RC4/MD5/SHA-1) in a security role | HIGH |
| Weak PRNG (`rand()`/`random()`) for tokens/keys/nonces | HIGH |
| Undersized key (RSA < 2048, AES < 128) | MEDIUM |
| `rand()` for non-security purposes (UI, testing) | MEDIUM (dismissed) |