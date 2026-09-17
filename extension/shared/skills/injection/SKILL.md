---
name: injection
description: Classify injection evidence — command (CWE-78), SQL (CWE-89), argument (CWE-88), XML/XPath (CWE-91), CRLF (CWE-93), log (CWE-117) injection via taint flow to dangerous sinks.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-78
  severity: CRITICAL
  domain: security
---

## Injection Analysis (CWE-78, CWE-89, CWE-88, CWE-91, CWE-93, CWE-117)

### Evidence Patterns

#### Command Injection (CWE-78) — category: `command_injection`
- **INJECTION event** with category `command_injection`
- Unsafe function: `system()`, `popen()` with user-controlled input
- No input sanitization or use of safe alternative (`execve`)

#### SQL Injection (CWE-89) — category: `sql_injection`
- **INJECTION event** with category `sql_injection`
- String concatenation/sprintf to build SQL query
- No parameterized query (`sqlite3_prepare_v2` + `sqlite3_bind_text`)

#### Argument Injection (CWE-88) — category: `argument_injection`
- **INJECTION event** with category `argument_injection`
- Process-startup API (`execv`/`execvp`/`execve`/`execl`/`execlp`/`execle`/`posix_spawn`/`posix_spawnp`) with a non-constant argument-array element
- The path argument (first param) is NOT this category — a tainted path is CWE-78

#### XML/XPath Injection (CWE-91) — category: `xml_xpath_injection` or `xml_injection`
- **INJECTION event** with category `xml_xpath_injection` (XPath eval) or `xml_injection` (XML parse)
- XPath: `xmlXPathEvalExpression()`, `xmlXPathEval()` with user-controlled expression
- XML: `xmlSAXParseDoc()`, `xmlParseDoc()`, `xmlReadDoc()` with user-controlled document
- Precompiled XPath (`xmlXPathCompiledEval` with a `xmlXPathCompileExpr` result) is safe

#### CRLF Injection (CWE-93) — category: `crlf_injection`
- **INJECTION event** with category `crlf_injection`
- `fprintf`/`fputs`/`snprintf`/`send`/`write` writing to a protocol-header context (FILE* named `sock`/`conn`/`socket`/`resp`/`header`, or format string contains `\r\n`/`HTTP/`/`Header:`/`Set-Cookie:`/`Content-Type:`)
- Header value parameter is non-constant

#### Log Injection (CWE-117) — category: `log_injection`
- **INJECTION event** with category `log_injection`
- `syslog()`/`vsyslog()` (unconditional log sink) or `fprintf`/`fputs`/`fwrite` to a log-file context (FILE* named `log`/`logfile`/`audit`/`fp_log`)
- Message parameter is non-constant
- Structured logging APIs (`log_structured`/`json_log`/`log_field_set`) are safe

### Safe Alternatives (P0 Exclusion)

| Unsafe | Safe Alternative | Why Safe |
|--------|-----------------|----------|
| `system(cmd)` | `execve(path, argv, env)` | No shell interpretation |
| `popen(cmd, ...)` | `fork + execv` | No shell interpretation |
| `sprintf(query, "...%s...", input)` | `sqlite3_prepare_v2 + bind` | Parameterized query |
| `xmlXPathEvalExpression(ctx, expr)` | `xmlXPathCompileExpr + xmlXPathCompiledEval` | Precompiled expression |
| `fprintf(sock, "Header: %s\r\n", input)` | `validate_header(input)` + `fprintf` | Header value sanitized |
| `syslog(LOG_INFO, "%s", input)` | `escape_newlines(input)` + `syslog` | Newlines stripped |

### Safe Wrappers (P1 Exemption)

| Wrapper | Guarantee |
|---------|-----------|
| `SafeQuery_prepare(db, sql)` | Uses prepared statement |
| `SafeQuery_bind_text(q, idx, val)` | Binds parameter safely |
| `SafeQuery_exec(q)` | Executes prepared statement |
| `SafeExecArg(path, argv)` | Validates exec argument array |
| `validate_exec_arg(arg)` | Validates single exec argument |
| `sanitize_argv(argv)` | Sanitizes argument array |
| `strip_crlf(s)` / `escape_crlf(s)` | Strips/escapes CRLF characters |
| `validate_header(h)` / `sanitize_header_value(h)` | Validates header value |
| `escape_newlines(s)` / `strip_newlines(s)` | Escapes/strips newlines for log |
| `validate_log(s)` / `sanitize_log_message(s)` | Validates log message |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `command_injection`: `system()` with user input, no sanitization | **confirmed** |
| `command_injection`: `system()` with user input + whitelist/validation | **false-positive** |
| `command_injection`: `execve()` with fixed path + args | **false-positive** |
| `sql_injection`: `sprintf` building SQL with user input | **confirmed** |
| `sql_injection`: `sqlite3_prepare_v2 + bind_text` | **false-positive** |
| `sql_injection`: `sqlite3_exec` with concatenated query | **confirmed** |
| `argument_injection`: `execve(path, argv)` with non-constant argv element, no sanitization | **confirmed** |
| `argument_injection`: `execve(path, argv)` with all-constant argv | **false-positive** |
| `argument_injection`: `SafeExecArg` wrapper used | **false-positive** |
| `xml_xpath_injection`: `xmlXPathEvalExpression(ctx, expr)` with user input | **confirmed** |
| `xml_xpath_injection`: `xmlXPathCompiledEval` with precompiled expression | **false-positive** |
| `xml_injection`: `xmlSAXParseDoc(NULL, doc, 0)` with user input | **confirmed** |
| `xml_injection`: `xmlSAXParseDoc` with constant document | **false-positive** |
| `crlf_injection`: `fprintf(sock, "Header: %s\r\n", input)` with user input | **confirmed** |
| `crlf_injection`: `fprintf(sock, "Header: const\r\n")` constant header | **false-positive** |
| `crlf_injection`: `validate_header(input)` used | **false-positive** |
| `log_injection`: `syslog(LOG_INFO, "%s", input)` with user input | **confirmed** |
| `log_injection`: `syslog(LOG_INFO, "const")` constant message | **false-positive** |
| `log_injection`: `escape_newlines(input)` used | **false-positive** |
| `log_injection`: Structured logging API (`log_structured`) | **false-positive** |

### CWE Boundary Disambiguation

#### CWE-78 (Command Injection) vs CWE-88 (Argument Injection)
- **CWE-78**: shell-invoking sink (`system`/`popen`/`ShellExecute`) OR execv* with **tainted path** (first argument) — shell metacharacter interpretation or path hijacking
- **CWE-88**: execv*/posix_spawn with **tainted argument array** (argv[1..]) — parameter boundary injection, no shell interpretation
- **Rule**: the injection point decides — path → CWE-78, argv → CWE-88

#### CWE-93 (CRLF Injection) vs CWE-117 (Log Injection)
- **CWE-93**: sink is a **protocol-header / HTTP-response** context (FILE* named sock/conn/socket/resp/header, or format string contains \r\n/HTTP//Header:/Set-Cookie:/Content-Type:)
- **CWE-117**: sink is a **log** context (`syslog`/`vsyslog` unconditionally, or FILE* named log/logfile/audit/fp_log)
- **Rule**: the sink semantic decides — protocol header → CWE-93, log → CWE-117
- **Fail-safe**: when the sink context is ambiguous (e.g. `fprintf(fp, "%s\n", x)` with an unclassifiable `fp`), **no event is produced** — better to miss a candidate than to misclassify it

### Common Edge Cases (P3)
- **Partial blacklist**: `is_safe_input()` filtering `;` but not `&&`, `||`, `$()` → **confirmed** (incomplete sanitization is still injectable)
- **TOCTOU**: Check then use with race window → **dismissed**
- **Format string**: `printf(user_input)` without format → **confirmed** (CWE-134)
- **Precompiled XPath**: `compiled = xmlXPathCompileExpr("//const"); xmlXPathCompiledEval(compiled, ctx)` → **false-positive** (parameterized)

### Fix Suggestions
- Command execution: Use `execve` with argument array, never `system()`
- SQL: Use prepared statements with parameter binding
- Argument injection: Validate argv elements with `SafeExecArg` or whitelist
- XML/XPath: Use precompiled XPath expressions with `xmlXPathCompileExpr`
- CRLF: Strip/escape `\r\n` in header values with `validate_header`
- Log: Strip/escape newlines in log messages with `escape_newlines`
- Input validation: Use whitelist, not blacklist

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Command injection (CWE-78): tainted input reaches `system`/`popen` | CRITICAL |
| SQL injection (CWE-89): tainted input reaches a concatenated/sprintf query | CRITICAL |
| Argument injection (CWE-88): tainted argv reaches `execve`/`posix_spawn` | HIGH |
| XML/XPath injection (CWE-91): tainted input reaches XPath/XML sink | HIGH |
| CRLF injection (CWE-93): tainted input reaches protocol-header sink | HIGH |
| Log injection (CWE-117): tainted input reaches log sink | MEDIUM |
| TOCTOU / unproven taint reaching the sink | HIGH (dismissed) |
