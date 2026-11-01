---
name: unbounded-length-copy
description: Classify unbounded-length-copy evidence — an externally-sourced length flowing into an allocation/copy size with no upper-bound guard. Maps to CWE-1284.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-1284
  severity: HIGH
  domain: security
---

## Unbounded Length Copy Analysis (CWE-1284)

### Evidence Pattern
An unbounded-length-copy candidate has:
- **unbounded_length**: an allocation/copy call (malloc/calloc/memcpy/memmove/
  strncpy/alloca) whose size argument is a length sourced from a network/file
  read return value (recv/recvfrom/recvmsg/read/pread/fread)
- **taint_source**: the length's origin (`fn:line`)
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `len-taint@<source-fn>:<line>` | the length originates here (a network/file read return) | the external trust boundary — is the source attacker-controlled? |
| `len-sink@<fn>:<line>` | the length reaches this allocation/copy as a size argument | the over-allocation / over-copy sink |
| `alloc_size@<var>` | the variable carrying the externally-sourced length | the tainted length |
| `guard@none-upper` | no upper-bound check dominates the sink (CFG proof) | the length is not clamped or range-checked before use |

The row is always `suspected` — the trust boundary is a semantic judgment. The
pipeline proved the length reaches the sink with NO upper-bound guard (a
`n < 0` check is NOT an upper bound); your job is to judge whether the source is
attacker-controlled (network) vs a trusted local file descriptor, and whether
the sink's destination capacity bounds the copy.

### Detection Logic
1. Find `len = recv(...)` / `len = read(...)` / `len = fread(...)` — a SINGLE
   assignment of a length-taint return to a local
2. Find an allocation/copy sink (malloc/calloc/memcpy/memmove/strncpy/alloca)
   whose size argument is that local
3. Skip when an upper-bound guard (`if (len <= MAX)`, a clamp) dominates the sink
4. Emit `UNBOUNDED_LENGTH` otherwise — always suspected

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
| `len-taint@recv` + `guard@none-upper` + the sink is an allocation/copy length | **confirmed** (attacker-controlled network length) |
| `len-taint@read`/`fread` on a trusted local file descriptor whose size is bounded by the file | **false-positive** (the source is not attacker-controlled) |
| A clamp/truncation that provably bounds the length BEFORE the sink | **false-positive** — the detector already skips these; do not dismiss on a clamp you cannot see, and never invent one |
| `len < 0` check only (not an upper bound) | **confirmed** (a negative check does not bound a large value) |

The `guard@none-upper` fact is a CFG proof of ABSENCE: the pipeline already
skipped every sink with an upper-bound guard, so do not spend a read hunting for
one the window cannot show. The decisive remaining question is the source's
trust boundary.

### Common False Positives
- A length with an upper-bound guard (`if (len > MAX) return;`, a clamp to
  `sizeof(buf)`) — the detector already skips these
- A trusted local file (`fread` on a config file) whose size is bounded upstream
- A `n < 0` check followed by a large value — **this is NOT an upper bound**, do
  not dismiss on it

### Fix Suggestions
- Range-check before use: `if (len > MAX_LEN) return -1;`
- Clamp the length: `len = min(len, sizeof(buf));`
- Use a bounded copy: `memcpy(dst, src, min(len, sizeof(dst)))`

### Examples

```c
// CONFIRMED — a network length flows into an allocation with no upper-bound clamp
ssize_t n = recv(fd, buf, sizeof buf, 0); char *p = malloc((size_t)n);

// DISMISSED — the length is clamped before the sink
if (n < 0 || n > MAX) return; char *p = malloc((size_t)n);
```

### Severity Matrix

`status` (confirmed / dismissed) and `severity`
(low / medium / high / critical) are **two independent axes** — never collapse
them into one column. `status` is the *evidence verdict* ("is it real?"),
`severity` is the *impact* ("how bad if real?"). The front-matter
`metadata.severity` is the type's **default** for a typical confirmed finding,
not a ceiling: pick each finding's severity from the table below.

| Severity | Meaning |
|----------|---------|
| CRITICAL | Attacker-reachable code execution / memory corruption, full data or credential compromise, or a live hardcoded secret |
| HIGH     | A certain or realistically-reachable memory-corruption / crash / DoS / auth-bypass / secret-disclosure defect |
| MEDIUM   | A real defect with limited impact (bounded resource leak, non-sensitive info disclosure, edge-case-only trigger) |
| LOW      | Defense-in-depth only, harmless dead code, or a weak-evidence issue that is dismissed |

**Verdicts**: `confirmed` (proved defect) or `dismissed` (everything else —
false positive OR a candidate you could not settle after reading its source).
`dismissed` → `low`.

| Shape | Reachability / exposure | Severity |
|-------|------------------------|----------|
| `len-taint@recv` (network) + allocation/copy length | attacker-controlled length → heap overflow | HIGH |
| `len-taint@read`/`fread` (local file) + copy length | trusted-but-unbounded source | MEDIUM |
