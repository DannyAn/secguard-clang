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

#### Value-proven secret — auto-confirmed by the pipeline
- **HARDCODED_SECRET event** with category `hardcoded_secret`
- The literal's VALUE is itself secret-shaped: a known token prefix (`sk-`, `AKIA`, `ghp_`, `xoxb-`, `-----BEGIN`, `eyJ`, ...), high Shannon entropy (>= 16 chars, >= 4.5 bits/char), or URL-embedded credentials (`mysql://root:hunter2@db`)
- Registry persistence with a secret-shaped value: `RegSetValueExA(..., "Password", ..., "sk-...")`

#### Name-only match — the AI decides
- **HARDCODED_SECRET event** with category `hardcoded_secret_name_only`
- Only the variable/field name is secret-bearing (`password`, `passwd`, `pwd`, `secret`, `api_key`, `apikey`, `access_key`, `private_key`, `token`, `credential`, `auth_key`, `client_secret`, `\bkey\b`, `\bpin\b`, `\bsalt\b`, `\bhash\b`) while the value is low-entropy
- This is where placeholders and test credentials land — judge each one

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `getenv("APP_PASSWORD")` | Loaded from environment at runtime |
| `read_config_file("/etc/app/secrets.conf")` | External config with restricted permissions |
| `vault_get_secret("db_password")` | Secrets manager (Vault, KMS) |
| Variable named `password` but assigned from `getenv()` | Not a literal — the detector never emits it |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Value has a known secret prefix, high entropy, or URL-embedded credentials | **confirmed** |
| `RegSetValueExA` persisting a secret-shaped value to a secret-named registry key | **confirmed** |
| Only the variable/field NAME matched the secret pattern (low-entropy value) | **suspected** — may be a real weak password, a placeholder, or a test value |
| Placeholder value (`"REPLACE_ME"`, `"YOUR_KEY_HERE"`, `"CHANGEME"`, `"xxx"`, empty) | **false-positive** |
| Test credential (`test_password = "test123"`, a `test/` path) | **suspected** (verify it is not used in production) |
| Short value that is not credential-like | **false-positive** |

### Fix Suggestions
- Load secrets from environment variables: `getenv("APP_PASSWORD")`
- Use a secrets manager (HashiCorp Vault, AWS KMS, Azure Key Vault)
- Store in config file with `0600` permissions, outside the repo
- Never commit credentials to source control
- Add `.gitignore` entries for secret files
- Rotate any credentials that were previously hardcoded
- Use `git-secrets` or `trufflehog` to scan for leaked credentials in git history