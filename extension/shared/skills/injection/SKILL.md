---
name: injection
description: Classify injection evidence — command injection (system/popen) and SQL injection (sprintf+sqlite3_exec). Maps to CWE-78, CWE-89.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-78
  severity: CRITICAL
---

## Injection Analysis (CWE-78, CWE-89)

### Evidence Patterns

#### Command Injection (CWE-78)
- **BUFFER_ACCESS event** with category `command_injection`
- Unsafe function: `system()`, `popen()` with user-controlled input
- No input sanitization or use of safe alternative (`execve`)

#### SQL Injection (CWE-89)
- **BUFFER_ACCESS event** with category `sql_injection`
- String concatenation/sprintf to build SQL query
- No parameterized query (`sqlite3_prepare_v2` + `sqlite3_bind_text`)

### Safe Alternatives (P0 Exclusion)

| Unsafe | Safe Alternative | Why Safe |
|--------|-----------------|----------|
| `system(cmd)` | `execve(path, argv, env)` | No shell interpretation |
| `popen(cmd, ...)` | `fork + execv` | No shell interpretation |
| `sprintf(query, "...%s...", input)` | `sqlite3_prepare_v2 + bind` | Parameterized query |

### Safe Wrappers (P1 Exemption)

| Wrapper | Guarantee |
|---------|-----------|
| `SafeQuery_prepare(db, sql)` | Uses prepared statement |
| `SafeQuery_bind_text(q, idx, val)` | Binds parameter safely |
| `SafeQuery_exec(q)` | Executes prepared statement |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `system()` with user input, no sanitization | **confirmed** |
| `system()` with user input + blacklist sanitization | **suspected** (incomplete) |
| `system()` with user input + whitelist/validation | **false-positive** |
| `execve()` with fixed path + args | **false-positive** |
| `sprintf` building SQL with user input | **confirmed** |
| `sqlite3_prepare_v2 + bind_text` | **false-positive** |
| `sqlite3_exec` with concatenated query | **confirmed** |

### Common Edge Cases (P3)
- **Partial blacklist**: `is_safe_input()` filtering `;` but not `&&`, `||`, `$()` → **suspected**
- **TOCTOU**: Check then use with race window → **suspected**
- **Format string**: `printf(user_input)` without format → **confirmed** (CWE-134)

### Fix Suggestions
- Command execution: Use `execve` with argument array, never `system()`
- SQL: Use prepared statements with parameter binding
- Input validation: Use whitelist, not blacklist
- Format strings: Use `printf("%s", user_input)`, never `printf(user_input)`