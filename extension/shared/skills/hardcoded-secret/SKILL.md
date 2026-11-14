---
name: hardcoded-secret
description: Classify hardcoded secret evidence — hardcoded passwords, API keys, tokens, and credential persistence. Maps to CWE-798.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-798
  severity: CRITICAL
  domain: trust
---

## Hardcoded Secret Analysis (CWE-798)

### Evidence Patterns

#### Value-proven secret — auto-confirmed by the pipeline
- **HARDCODED_SECRET event** with category `hardcoded_secret` and a `value_proven` marker
- The literal's VALUE is itself secret-shaped: a known token prefix (`sk-`, `AKIA`, `ghp_`, `xoxb-`, `-----BEGIN`, `eyJ`, ...), high Shannon entropy (>= 16 chars, >= 4.5 bits/char), or URL-embedded credentials (`mysql://root:hunter2@db`)
- Registry persistence with a secret-shaped value: `RegSetValueExA(..., "Password", ..., "sk-...")`

#### Name-only match — the AI decides
- **hardcoded_secret**: the candidate site with category `hardcoded_secret` and NO `value_proven` marker
- **match_kind**: the name-only verdict context — the variable/field name is secret-bearing (`password`, `passwd`, `pwd`, `secret`, `api_key`, `apikey`, `access_key`, `private_key`, `token`, `credential`, `auth_key`, `client_secret`, `\bkey\b`, `\bpin\b`, `\bsalt\b`, `\bhash\b`) while the value is low-entropy
- **secret_value**: the literal MASKED (first 4 chars + total length, e.g. `"REPL… (11 chars)"`): judge placeholder (`REPL…`/`CHANG…`/`xxxx…`) vs test value (`test…`) vs real weak credential (`admi…`) from the prefix and length; the full literal is withheld from the evidence file, but it is in the ±8 Code Context window of the candidate line
- This is where placeholders and test credentials land — judge each one

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `value-shape@<masked>` | the literal's masked shape (4-char prefix + length; the report must not become the leak it reports) | a placeholder (REPLACE…) or test value (test…) prefix is dismissed; a real credential shape (key-style prefix, credential length) is confirmed |

The masked shape is the whole verdict basis — judge from the prefix and
length, never demand the raw literal.

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `getenv("APP_PASSWORD")` | Loaded from environment at runtime |
| `read_config_file("/etc/app/secrets.conf")` | External config with restricted permissions |
| `vault_get_secret("db_password")` | Secrets manager (Vault, KMS) |
| Variable named `password` but assigned from `getenv()` | Not a literal — the detector never emits it |

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
| Value has a known secret prefix, high entropy, or URL-embedded credentials | **confirmed** |
| `RegSetValueExA` persisting a secret-shaped value to a secret-named registry key | **confirmed** |
| Only the variable/field NAME matched the secret pattern (low-entropy value) | **judge the value, not the name** — a placeholder (`REPLACE…`) is **false-positive**; a short non-credential-like value is **false-positive**; a real-looking credential (`password = "hunter2"`, `"admin123"`) is a **confirmed** weak credential even though its entropy is low |
| Placeholder value (`"REPLACE_ME"`, `"YOUR_KEY_HERE"`, `"CHANGEME"`, `"xxx"`, empty) | **false-positive** |
| Test credential (`test_password = "test123"`, a `test/` path) | **dismissed** — but a leaked test key is still a leaked key; dismiss only when the Code Context proves it cannot reach production |
| Short value that is not credential-like | **false-positive** |

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Move the secret out of source: load it from an environment
  variable (`getenv("APP_PASSWORD")`) or a secrets manager (Vault/KMS/Key Vault),
  or an out-of-repo config file with `0600` permissions.
- **Required conditions** — The runtime must actually inject the secret (env/CI/
  secret store) before the code path runs; document that dependency. Always rotate
  the exposed credential — removing it from source is not enough — and scrub it
  from git history (`git-secrets`/`trufflehog`).
- **Validation** — Confirm the code reads the secret from the new source, the
  literal no longer appears in the tree or history, and the re-scan no longer
  reports the location.

### Examples

```c
// CONFIRMED — a real weak credential embedded as a literal
char *pwd = "admin123";

// DISMISSED — a placeholder, not a live credential
char *pwd = "REPLACE_ME";
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Value-proven secret (known prefix / high entropy / URL credentials) in source | CRITICAL |
| Registry persistence of a secret-shaped value | CRITICAL |
| Test credential suspected to be used in production | HIGH (dismissed) |
| Name-only match, low-entropy, likely placeholder | MEDIUM (dismissed) |