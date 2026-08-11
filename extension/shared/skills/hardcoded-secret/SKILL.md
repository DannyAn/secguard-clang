---
name: hardcoded-secret
description: Classify hardcoded secret evidence — hardcoded passwords, API keys, tokens, and credential persistence. Maps to CWE-798.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-798
  severity: CRITICAL
  domain: trust
---

## Hardcoded Secret Analysis (CWE-798)

### Evidence Patterns

#### Hardcoded Credentials (CWE-798)
- **HARDCODED_SECRET event** with category `hardcoded_password` / `hardcoded_key` / `hardcoded_token`
- Pattern: String literal assigned to variable named `password`, `passwd`, `key`, `secret`, `token`, `api_key`
- Credential embedded directly in source code

#### Credential Persistence (CWE-798)
- **HARDCODED_SECRET event** with category `credential_persistence`
- Pattern: `RegSetValueExA(..., "Password", ...)` writing credentials to registry
- Credentials stored in persistent storage without encryption

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `getenv("APP_PASSWORD")` | Loaded from environment at runtime |
| `read_config_file("/etc/app/secrets.conf")` | External config with restricted permissions |
| `vault_get_secret("db_password")` | Secrets manager (Vault, KMS) |
| Variable named `password` but assigned from `getenv()` | Not hardcoded |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| String literal assigned to `password`/`key`/`secret`/`token` variable | **confirmed** |
| `RegSetValueExA` writing credential to registry | **confirmed** |
| Variable named `password` but value from `getenv()` / config file | **false-positive** |
| String literal that is a placeholder (`"REPLACE_ME"`, `"YOUR_KEY_HERE"`) | **false-positive** |
| String literal in test code (`test_password = "test123"`) | **suspected** (verify it's not used in production) |
| Short string that isn't credential-like | **false-positive** |

### Fix Suggestions
- Load secrets from environment variables: `getenv("APP_PASSWORD")`
- Use a secrets manager (HashiCorp Vault, AWS KMS, Azure Key Vault)
- Store in config file with `0600` permissions, outside the repo
- Never commit credentials to source control
- Add `.gitignore` entries for secret files
- Rotate any credentials that were previously hardcoded
- Use `git-secrets` or `trufflehog` to scan for leaked credentials in git history