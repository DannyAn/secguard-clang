---
name: argument-type
description: Classify argument-type evidence — an explicit pointer cast passes an incompatible object type to a function parameter. Maps to CWE-686.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-686
  severity: MEDIUM
  domain: contract
---

## Function Argument Type Mismatch Analysis (CWE-686 / CERT EXP37-C)

`contract_kind: explicit` — the contract is the callee's declared parameter type.

### Evidence Pattern
An argument-type candidate has:
- **argument_type_mismatch**: A direct call passes an argument that is an
  **explicit cast to a pointer type**, where the cast's pointed-to object type
  is incompatible with the source object's type — e.g. `void f(uint *p); bool b;
  f((uint *)&b);` (the callee reads a 1-byte `bool` as a 4-byte `uint`).
- **expected** / **actual** / **cast**: the parameter type (`uint *`), the
  argument's pre-cast pointer type (`bool *`), and the explicit cast target.
- **call_path**: The function is reachable from an entry point.

The detector only emits **direct calls** with an **explicit pointer cast**, and
only numeric-object reinterpretations: the target provably reads more bytes than
the source object holds (bool→uint, uint32→uint64) or changes the representation
kind (int↔float). It does **not** flag `void *`, char/byte casts, identical
types, or same-size integer reinterpretation — those are legal C boundaries.

### Detection Logic
1. Resolve the callee of a direct call and its parameter type spellings
   (cross-file, from definitions and prototypes).
2. For each argument that is an explicit cast to a pointer type, extract the
   cast target pointed-to type and the source object's type (`&x` → x's type;
   a pointer variable → its pointed-to type).
3. Filter legal conversions: identical, `void *`, byte (`char`) target,
   same-size integer, target-not-wider.
4. Emit `ARGUMENT_TYPE_MISMATCH` with `category: argument_type_mismatch` when
   the target provably reads more bytes than the source object, or the
   representation kind differs.

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `f((uint *)&bool_flag)` — the callee writes/reads a `bool` object through a `uint *`; object size 1 vs 4, overrun or type-pun | **confirmed** |
| `f((uint64_t *)&uint32_val)` — reads 8 bytes from a 4-byte object | **confirmed** |
| `f((float *)&int_val)` / `f((int *)&float_val)` — representation kind differs | **confirmed** |
| The cast target is `void *` or a byte type (`char *`, `unsigned char *`) | **false-positive** (legal boundary) |
| The pointed-to types are identical, or same-size integers (`int`↔`unsigned`) | **false-positive** (benign reinterpretation) |
| The cast is part of a documented ABI/opaque-handle pattern (`(T*)&payload`, serializer) | **false-positive** (intentional boundary) |
| An indirect call / function pointer / aggregate (`struct A`↔`struct B`) cast | **dismissed** (out of phase-1 scope — low evidence) |

### Common False Positives
- `void *` / `char *` byte access (`(char *)&x`, memcpy-style, serialization)
- Same-size integer reinterpretation (`int` ↔ `unsigned int`, `uint32_t` ↔ `int`)
- Opaque-handle / ABI-compat casts where the object is intentionally accessed
  through a different-but-compatible type
- Casts whose source is an opaque pointer or a function-call result the detector
  could not resolve (it skips those)

### Fix Suggestions
- Pass an object whose declared type matches the parameter, or widen the object
  (`uint32_t x` → `uint64_t x`) so the callee reads no more than the object holds.
- Change the parameter to `void *` (or a byte type) when the callee is a generic
  consumer that should not assume the object type.
- Remove the cast and fix the object's declared type so no reinterpretation occurs.

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary
(confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Target reads more bytes than the source object (bool→uint, uint32→uint64) on an attacker-influenced value | HIGH |
| Representation-kind change (int↔float) that corrupts a value used in a bounds check or size | MEDIUM |
| Incompatible cast on a local, non-reachable or defensive path | LOW (dismissed) |
