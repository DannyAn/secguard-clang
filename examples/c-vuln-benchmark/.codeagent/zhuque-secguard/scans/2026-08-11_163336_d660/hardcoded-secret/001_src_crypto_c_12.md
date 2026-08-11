# Hardcoded Secret in authenticate_user

**CWE:** CWE-798

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/crypto.c:12`
- **Function:** `authenticate_user`
- **Variable:** `g_api_key`

## Evidence

- **hardcoded_secret:** hardcoded secret in authenticate_user at line 12
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Remove the hardcoded credential from `authenticate_user` and load it from a secure
source at runtime:

```c
// BAD:  const char *password = "admin123";
// GOOD: read from env var, vault, or config file with restricted perms
const char *password = getenv("APP_PASSWORD"));
if (!password) { return -1; }
```

Store secrets in a secrets manager (HashiCorp Vault, cloud KMS) or a
file with `0600` permissions outside the repo. Never commit credentials
to source control. Rotate any credentials that were previously hardcoded.
